Response:
The user wants me to analyze the provided C++ header file `v8-object.h` from the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The file is named `v8-object.h`, which strongly suggests it's about the representation and manipulation of JavaScript objects within the V8 engine's C++ API. This will be the central theme of the summary.

2. **Check for Torque:** The prompt asks if the file ends with `.tq`. Since it ends with `.h`, it's a C++ header, not a Torque file. State this clearly.

3. **Relationship to JavaScript:** The core of the file deals with objects, a fundamental concept in JavaScript. Point out the direct correlation.

4. **List Key Functionalities:** Go through the header file and identify the main classes and their methods. Group related functionalities together. This involves:
    * **`Private` class:** For private symbols.
    * **`PropertyDescriptor` class:**  For defining property attributes.
    * **Enums:** `PropertyAttribute`, `PropertyFilter`, `SideEffectType`, `KeyCollectionMode`, `IndexFilter`, `KeyConversionMode`, `IntegrityLevel`. These define options and flags related to object properties.
    * **`Object` class:** This is the most important. List its prominent methods, focusing on:
        * Property access (getting, setting, deleting).
        * Property attributes (defining, getting).
        * Prototype manipulation.
        * Internal fields.
        * Wrapping/unwrapping C++ objects.
        * Iteration/enumeration.
        * Calling objects as functions/constructors.
        * Utility functions (cloning, getting context, etc.).

5. **JavaScript Examples:**  For each key functionality identified, provide a simple JavaScript example to illustrate the concept. Keep the examples concise and focused on the specific API element. For example, for `Set`, use a simple assignment. For `DefineProperty`, show how to set attributes.

6. **Code Logic/Reasoning (if applicable):** In this part of the header, the logic is primarily about defining the *interface* for interacting with objects. There aren't complex algorithms. However, explain the *purpose* behind certain methods. For example, explain *why* `CreateDataProperty` is simpler than `DefineProperty`. For the internal fields, explain their purpose in extending object behavior.

7. **Common Programming Errors:** Think about how a C++ developer using this API might make mistakes. Common errors include:
    * Incorrectly using `MaybeLocal` and forgetting to check for empty results.
    * Mismatched types when using internal fields.
    * Incorrect usage of `Wrap` and `Unwrap` (tag mismatches).
    * Not understanding the implications of property attributes.

8. **Assumptions (Input/Output):**  For demonstrating code logic, create simple scenarios. For instance, setting a property, getting a property, or defining a read-only property. Provide the expected output.

9. **Overall Summary (for Part 1):**  Concisely summarize the main purpose of the header file and the key functionalities it provides for manipulating JavaScript objects within the V8 engine's C++ embedding API.

10. **Structure and Formatting:**  Organize the information logically using headings, bullet points, and code blocks for clarity. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Just list all the methods.
* **Correction:** Group related methods together thematically for better understanding.
* **Initial thought:** Provide very technical explanations of each method.
* **Correction:** Focus on the *purpose* and provide corresponding JavaScript examples for better comprehension.
* **Initial thought:**  Only focus on the `Object` class.
* **Correction:**  Recognize the importance of `Private` and `PropertyDescriptor` and include them.
* **Initial thought:**  The "code logic" section should involve complex examples.
* **Correction:** The focus here is on understanding the intent behind the methods, not complex algorithmic flows within this header. Keep the examples simple.
* **Initial thought:**  Overlook common errors.
* **Correction:**  Actively think about potential pitfalls for developers using this API.
好的，让我们来分析一下 `v8/include/v8-object.h` 这个 V8 源代码文件。

**功能归纳（第 1 部分）：**

`v8/include/v8-object.h` 是 V8 JavaScript 引擎的 C++ API 头文件，它定义了与 JavaScript 对象相关的核心接口和类。其主要功能可以归纳为：

1. **定义了 JavaScript 对象的 C++ 表示：**  通过 `v8::Object` 类，提供了在 C++ 中操作 JavaScript 对象的方法。这包括创建、访问、修改对象的属性，以及调用对象的方法。

2. **提供访问和修改对象属性的接口：**  定义了 `Set`, `Get`, `CreateDataProperty`, `DefineProperty`, `Delete`, `Has` 等方法，用于操作对象的属性，包括数据属性和访问器属性。

3. **支持属性的各种特性控制：**  通过 `PropertyDescriptor` 类和 `PropertyAttribute` 枚举，允许开发者精细地控制属性的特性，如可写性、可枚举性和可配置性。

4. **支持私有属性：**  引入了 `v8::Private` 类，允许创建和操作私有符号，这是 JavaScript 中用于实现信息隐藏的机制。

5. **提供操作对象原型链的接口：**  定义了 `GetPrototype`, `SetPrototype`, `FindInstanceInPrototypeChain` 等方法，允许 C++ 代码访问和修改对象的原型链。

6. **支持内部字段：**  `Object` 类提供了 `GetInternalField` 和 `SetInternalField` 等方法，允许 C++ 代码为 JavaScript 对象关联额外的本地数据，这常用于实现宿主对象或扩展 JavaScript 功能。

7. **支持对象包装和解包：**  提供了 `Wrap` 和 `Unwrap` 静态方法，允许将 C++ 对象实例与 JavaScript 对象关联起来，这对于在 C++ 中实现 JavaScript 对象的原生扩展非常重要。

8. **提供获取对象信息的方法：**  例如 `GetPropertyNames`, `GetOwnPropertyNames`, `GetConstructorName`, `InternalFieldCount`, `GetIdentityHash`, `GetCreationContext` 等，允许 C++ 代码获取关于对象的各种元数据。

9. **定义了与访问器属性相关的回调类型：**  如 `AccessorNameGetterCallback` 和 `AccessorNameSetterCallback`，用于处理访问器属性的读取和设置操作。

10. **定义了属性过滤器和键值收集模式：**  通过 `PropertyFilter`, `KeyCollectionMode`, `IndexFilter`, `KeyConversionMode` 等枚举，允许更精细地控制属性的枚举和获取方式。

**关于文件类型和 JavaScript 关联：**

* 正如您所指出的，`v8/include/v8-object.h` 以 `.h` 结尾，因此它是一个 **C++ 头文件**，而不是 Torque 源代码文件（Torque 文件通常以 `.tq` 结尾）。
* 该文件与 JavaScript 的功能 **密切相关**。它定义了 C++ 中操作 JavaScript 对象的核心 API。  几乎所有 JavaScript 中与对象相关的操作，都可以在这个头文件中找到对应的 C++ 接口。

**JavaScript 举例说明：**

以下是一些 `v8/include/v8-object.h` 中定义的 C++ 功能与 JavaScript 代码的对应示例：

* **`Set` 和 `Get`:**

```javascript
const obj = {};
obj.name = 'John'; // 对应 C++ 的 Object::Set
console.log(obj.name); // 对应 C++ 的 Object::Get
```

* **`CreateDataProperty` 和 `DefineProperty`:**

```javascript
const obj = {};
Object.defineProperty(obj, 'age', { value: 30 }); // 对应 C++ 的 Object::DefineProperty
obj.newProperty = 'test'; // 对应 C++ 的 Object::CreateDataProperty (默认属性)
```

* **`Delete`:**

```javascript
const obj = { name: 'Alice' };
delete obj.name; // 对应 C++ 的 Object::Delete
```

* **`Has`:**

```javascript
const obj = { city: 'New York' };
console.log('city' in obj); // 对应 C++ 的 Object::Has
```

* **`GetPrototype` 和 `SetPrototype`:**

```javascript
const parent = { greeting: 'Hello' };
const child = Object.create(parent); // child 的原型是 parent
console.log(child.greeting); // 访问原型链上的属性

// 动态修改原型
Object.setPrototypeOf(child, { farewell: 'Goodbye' });
// 现在 child 的原型变成了 { farewell: 'Goodbye' }
```

* **内部字段（通常不直接在 JavaScript 中操作，但在 C++ 扩展中使用）：**

```c++
// C++ 代码示例 (简化)
void MyObject::GetValue(const FunctionCallbackInfo<Value>& args) {
  Local<Object> self = args.This();
  Local<External> wrap = Local<External>::Cast(self->GetInternalField(0));
  MyNativeClass* nativeObject = static_cast<MyNativeClass*>(wrap->Value());
  args.GetReturnValue().Set(String::NewFromUtf8(args.GetIsolate(), nativeObject->value_.c_str()));
}
```

**代码逻辑推理和假设输入/输出：**

让我们以 `Object::Set` 方法为例进行简单的逻辑推理：

**假设输入：**

* `context`: 一个有效的 V8 上下文。
* `key`:  一个 `Local<Value>`，例如一个 `String::NewFromUtf8(isolate, "propertyName")` 表示属性名。
* `value`: 一个 `Local<Value>`，例如 `Integer::New(isolate, 123)` 表示属性值。
* 目标 `Object` 是一个空的 JavaScript 对象 `{}`。

**代码逻辑 (简述)：**

`Object::Set` 方法会尝试在目标对象上设置一个名为 `key` 的属性，并将其值设置为 `value`。这会涉及到以下步骤：

1. **类型转换和检查：** 确保 `key` 可以转换为有效的属性名。
2. **查找属性：** 检查对象自身或其原型链上是否已存在该属性。
3. **设置属性：**
   * 如果属性不存在，则创建一个新的数据属性并设置值。
   * 如果属性存在但可写，则更新其值。
   * 如果属性存在但不可写，则设置操作可能会失败（取决于严格模式）。
   * 如果存在 setter 访问器，则调用 setter 函数。
4. **返回结果：** 返回一个 `Maybe<bool>`，指示设置操作是否成功。

**预期输出：**

如果设置成功，`Maybe<bool>` 将包含 `Just(true)`。目标对象将变为 `{ propertyName: 123 }`。

**用户常见的编程错误：**

1. **忘记处理 `MaybeLocal` 和 `Maybe` 返回值：** 很多 V8 API 方法返回 `MaybeLocal<T>` 或 `Maybe<T>`，表示操作可能失败。开发者需要检查返回值是否为空 (`IsEmpty()`) 或成功 (`IsJust()`)，否则可能会导致未定义的行为或崩溃。

   ```c++
   Local<Context> context = isolate->GetCurrentContext();
   Local<Object> obj = Object::New(isolate);
   Local<String> key = String::NewFromUtf8(isolate, "test");
   Local<String> value = String::NewFromUtf8(isolate, "value");

   // 错误的做法：直接使用 MaybeLocal 的结果
   // obj->Set(context, key, value); // 可能崩溃

   // 正确的做法：检查返回值
   Maybe<bool> result = obj->Set(context, key, value);
   if (result.IsJust() && result.FromJust()) {
     // 设置成功
   } else {
     // 设置失败，处理错误
   }
   ```

2. **在不正确的上下文中使用对象：** V8 对象与特定的 `Isolate` 和 `Context` 关联。在不同的 `Isolate` 或 `Context` 中使用对象可能会导致错误。

3. **对不可配置的属性进行操作：** 尝试删除或重新定义一个不可配置的属性将会失败，但在非严格模式下可能不会抛出错误，导致难以调试的问题。

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'constant', { value: 10, configurable: false });
   delete obj.constant; // 非严格模式下静默失败
   Object.defineProperty(obj, 'constant', { writable: true }); // 抛出 TypeError
   ```

4. **错误地使用内部字段：**  内部字段的索引必须正确，并且存储和检索的数据类型必须一致。类型不匹配会导致未定义的行为。

   ```c++
   // 假设在创建对象时设置了内部字段
   Local<Object> myObject = ...;
   myObject->SetInternalField(0, External::New(isolate, new MyNativeClass()));

   // 错误地尝试将内部字段作为字符串访问
   // Local<String> wrongValue = myObject->GetInternalField(0).As<String>(); // 类型错误

   // 正确的做法
   Local<External> external = Local<External>::Cast(myObject->GetInternalField(0));
   MyNativeClass* nativeObject = static_cast<MyNativeClass*>(external->Value());
   ```

希望以上分析对您有所帮助！请继续提供第 2 部分的内容。

Prompt: 
```
这是目录为v8/include/v8-object.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-object.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_OBJECT_H_
#define INCLUDE_V8_OBJECT_H_

#include "v8-internal.h"           // NOLINT(build/include_directory)
#include "v8-local-handle.h"       // NOLINT(build/include_directory)
#include "v8-maybe.h"              // NOLINT(build/include_directory)
#include "v8-persistent-handle.h"  // NOLINT(build/include_directory)
#include "v8-primitive.h"          // NOLINT(build/include_directory)
#include "v8-sandbox.h"            // NOLINT(build/include_directory)
#include "v8-traced-handle.h"      // NOLINT(build/include_directory)
#include "v8-value.h"              // NOLINT(build/include_directory)
#include "v8config.h"              // NOLINT(build/include_directory)

namespace v8 {

class Array;
class Function;
class FunctionTemplate;
template <typename T>
class PropertyCallbackInfo;

/**
 * A private symbol
 *
 * This is an experimental feature. Use at your own risk.
 */
class V8_EXPORT Private : public Data {
 public:
  /**
   * Returns the print name string of the private symbol, or undefined if none.
   */
  Local<Value> Name() const;

  /**
   * Create a private symbol. If name is not empty, it will be the description.
   */
  static Local<Private> New(Isolate* isolate,
                            Local<String> name = Local<String>());

  /**
   * Retrieve a global private symbol. If a symbol with this name has not
   * been retrieved in the same isolate before, it is created.
   * Note that private symbols created this way are never collected, so
   * they should only be used for statically fixed properties.
   * Also, there is only one global name space for the names used as keys.
   * To minimize the potential for clashes, use qualified names as keys,
   * e.g., "Class#property".
   */
  static Local<Private> ForApi(Isolate* isolate, Local<String> name);

  V8_INLINE static Private* Cast(Data* data);

 private:
  Private();

  static void CheckCast(Data* that);
};

/**
 * An instance of a Property Descriptor, see Ecma-262 6.2.4.
 *
 * Properties in a descriptor are present or absent. If you do not set
 * `enumerable`, `configurable`, and `writable`, they are absent. If `value`,
 * `get`, or `set` are absent, but you must specify them in the constructor, use
 * empty handles.
 *
 * Accessors `get` and `set` must be callable or undefined if they are present.
 *
 * \note Only query properties if they are present, i.e., call `x()` only if
 * `has_x()` returns true.
 *
 * \code
 * // var desc = {writable: false}
 * v8::PropertyDescriptor d(Local<Value>()), false);
 * d.value(); // error, value not set
 * if (d.has_writable()) {
 *   d.writable(); // false
 * }
 *
 * // var desc = {value: undefined}
 * v8::PropertyDescriptor d(v8::Undefined(isolate));
 *
 * // var desc = {get: undefined}
 * v8::PropertyDescriptor d(v8::Undefined(isolate), Local<Value>()));
 * \endcode
 */
class V8_EXPORT PropertyDescriptor {
 public:
  // GenericDescriptor
  PropertyDescriptor();

  // DataDescriptor
  explicit PropertyDescriptor(Local<Value> value);

  // DataDescriptor with writable property
  PropertyDescriptor(Local<Value> value, bool writable);

  // AccessorDescriptor
  PropertyDescriptor(Local<Value> get, Local<Value> set);

  ~PropertyDescriptor();

  Local<Value> value() const;
  bool has_value() const;

  Local<Value> get() const;
  bool has_get() const;
  Local<Value> set() const;
  bool has_set() const;

  void set_enumerable(bool enumerable);
  bool enumerable() const;
  bool has_enumerable() const;

  void set_configurable(bool configurable);
  bool configurable() const;
  bool has_configurable() const;

  bool writable() const;
  bool has_writable() const;

  struct PrivateData;
  PrivateData* get_private() const { return private_; }

  PropertyDescriptor(const PropertyDescriptor&) = delete;
  void operator=(const PropertyDescriptor&) = delete;

 private:
  PrivateData* private_;
};

/**
 * PropertyAttribute.
 */
enum PropertyAttribute {
  /** None. **/
  None = 0,
  /** ReadOnly, i.e., not writable. **/
  ReadOnly = 1 << 0,
  /** DontEnum, i.e., not enumerable. **/
  DontEnum = 1 << 1,
  /** DontDelete, i.e., not configurable. **/
  DontDelete = 1 << 2
};

/**
 * Accessor[Getter|Setter] are used as callback functions when setting|getting
 * a particular data property. See Object::SetNativeDataProperty and
 * ObjectTemplate::SetNativeDataProperty methods.
 */
using AccessorNameGetterCallback =
    void (*)(Local<Name> property, const PropertyCallbackInfo<Value>& info);

using AccessorNameSetterCallback =
    void (*)(Local<Name> property, Local<Value> value,
             const PropertyCallbackInfo<void>& info);

/**
 * Access control specifications.
 *
 * Some accessors should be accessible across contexts. These
 * accessors have an explicit access control parameter which specifies
 * the kind of cross-context access that should be allowed.
 *
 */
enum V8_DEPRECATE_SOON(
    "This enum is no longer used and will be removed in V8 12.9.")
    AccessControl {
      DEFAULT V8_ENUM_DEPRECATE_SOON("not used") = 0,
    };

/**
 * Property filter bits. They can be or'ed to build a composite filter.
 */
enum PropertyFilter {
  ALL_PROPERTIES = 0,
  ONLY_WRITABLE = 1,
  ONLY_ENUMERABLE = 2,
  ONLY_CONFIGURABLE = 4,
  SKIP_STRINGS = 8,
  SKIP_SYMBOLS = 16
};

/**
 * Options for marking whether callbacks may trigger JS-observable side effects.
 * Side-effect-free callbacks are allowlisted during debug evaluation with
 * throwOnSideEffect. It applies when calling a Function, FunctionTemplate,
 * or an Accessor callback. For Interceptors, please see
 * PropertyHandlerFlags's kHasNoSideEffect.
 * Callbacks that only cause side effects to the receiver are allowlisted if
 * invoked on receiver objects that are created within the same debug-evaluate
 * call, as these objects are temporary and the side effect does not escape.
 */
enum class SideEffectType {
  kHasSideEffect,
  kHasNoSideEffect,
  kHasSideEffectToReceiver
};

/**
 * Keys/Properties filter enums:
 *
 * KeyCollectionMode limits the range of collected properties. kOwnOnly limits
 * the collected properties to the given Object only. kIncludesPrototypes will
 * include all keys of the objects's prototype chain as well.
 */
enum class KeyCollectionMode { kOwnOnly, kIncludePrototypes };

/**
 * kIncludesIndices allows for integer indices to be collected, while
 * kSkipIndices will exclude integer indices from being collected.
 */
enum class IndexFilter { kIncludeIndices, kSkipIndices };

/**
 * kConvertToString will convert integer indices to strings.
 * kKeepNumbers will return numbers for integer indices.
 */
enum class KeyConversionMode { kConvertToString, kKeepNumbers, kNoNumbers };

/**
 * Integrity level for objects.
 */
enum class IntegrityLevel { kFrozen, kSealed };

/**
 * A JavaScript object (ECMA-262, 4.3.3)
 */
class V8_EXPORT Object : public Value {
 public:
  /**
   * Set only return Just(true) or Empty(), so if it should never fail, use
   * result.Check().
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> Set(Local<Context> context,
                                        Local<Value> key, Local<Value> value);
  V8_WARN_UNUSED_RESULT Maybe<bool> Set(Local<Context> context,
                                        Local<Value> key, Local<Value> value,
                                        MaybeLocal<Object> receiver);

  V8_WARN_UNUSED_RESULT Maybe<bool> Set(Local<Context> context, uint32_t index,
                                        Local<Value> value);

  /**
   * Implements CreateDataProperty(O, P, V), see
   * https://tc39.es/ecma262/#sec-createdataproperty.
   *
   * Defines a configurable, writable, enumerable property with the given value
   * on the object unless the property already exists and is not configurable
   * or the object is not extensible.
   *
   * Returns true on success.
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> CreateDataProperty(Local<Context> context,
                                                       Local<Name> key,
                                                       Local<Value> value);
  V8_WARN_UNUSED_RESULT Maybe<bool> CreateDataProperty(Local<Context> context,
                                                       uint32_t index,
                                                       Local<Value> value);

  /**
   * Implements [[DefineOwnProperty]] for data property case, see
   * https://tc39.es/ecma262/#table-essential-internal-methods.
   *
   * In general, CreateDataProperty will be faster, however, does not allow
   * for specifying attributes.
   *
   * Returns true on success.
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> DefineOwnProperty(
      Local<Context> context, Local<Name> key, Local<Value> value,
      PropertyAttribute attributes = None);

  /**
   * Implements Object.defineProperty(O, P, Attributes), see
   * https://tc39.es/ecma262/#sec-object.defineproperty.
   *
   * The defineProperty function is used to add an own property or
   * update the attributes of an existing own property of an object.
   *
   * Both data and accessor descriptors can be used.
   *
   * In general, CreateDataProperty is faster, however, does not allow
   * for specifying attributes or an accessor descriptor.
   *
   * The PropertyDescriptor can change when redefining a property.
   *
   * Returns true on success.
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> DefineProperty(
      Local<Context> context, Local<Name> key, PropertyDescriptor& descriptor);

  V8_WARN_UNUSED_RESULT MaybeLocal<Value> Get(Local<Context> context,
                                              Local<Value> key);
  V8_WARN_UNUSED_RESULT MaybeLocal<Value> Get(Local<Context> context,
                                              Local<Value> key,
                                              MaybeLocal<Object> receiver);

  V8_WARN_UNUSED_RESULT MaybeLocal<Value> Get(Local<Context> context,
                                              uint32_t index);

  /**
   * Gets the property attributes of a property which can be None or
   * any combination of ReadOnly, DontEnum and DontDelete. Returns
   * None when the property doesn't exist.
   */
  V8_WARN_UNUSED_RESULT Maybe<PropertyAttribute> GetPropertyAttributes(
      Local<Context> context, Local<Value> key);

  /**
   * Implements Object.getOwnPropertyDescriptor(O, P), see
   * https://tc39.es/ecma262/#sec-object.getownpropertydescriptor.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Value> GetOwnPropertyDescriptor(
      Local<Context> context, Local<Name> key);

  /**
   * Object::Has() calls the abstract operation HasProperty(O, P), see
   * https://tc39.es/ecma262/#sec-hasproperty. Has() returns
   * true, if the object has the property, either own or on the prototype chain.
   * Interceptors, i.e., PropertyQueryCallbacks, are called if present.
   *
   * Has() has the same side effects as JavaScript's `variable in object`.
   * For example, calling Has() on a revoked proxy will throw an exception.
   *
   * \note Has() converts the key to a name, which possibly calls back into
   * JavaScript.
   *
   * See also v8::Object::HasOwnProperty() and
   * v8::Object::HasRealNamedProperty().
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> Has(Local<Context> context,
                                        Local<Value> key);

  V8_WARN_UNUSED_RESULT Maybe<bool> Delete(Local<Context> context,
                                           Local<Value> key);

  V8_WARN_UNUSED_RESULT Maybe<bool> Has(Local<Context> context, uint32_t index);

  V8_WARN_UNUSED_RESULT Maybe<bool> Delete(Local<Context> context,
                                           uint32_t index);

  /**
   * Sets an accessor property like Template::SetAccessorProperty, but
   * this method sets on this object directly.
   */
  void SetAccessorProperty(Local<Name> name, Local<Function> getter,
                           Local<Function> setter = Local<Function>(),
                           PropertyAttribute attributes = None);

  /**
   * Sets a native data property like Template::SetNativeDataProperty, but
   * this method sets on this object directly.
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> SetNativeDataProperty(
      Local<Context> context, Local<Name> name,
      AccessorNameGetterCallback getter,
      AccessorNameSetterCallback setter = nullptr,
      Local<Value> data = Local<Value>(), PropertyAttribute attributes = None,
      SideEffectType getter_side_effect_type = SideEffectType::kHasSideEffect,
      SideEffectType setter_side_effect_type = SideEffectType::kHasSideEffect);

  /**
   * Attempts to create a property with the given name which behaves like a data
   * property, except that the provided getter is invoked (and provided with the
   * data value) to supply its value the first time it is read. After the
   * property is accessed once, it is replaced with an ordinary data property.
   *
   * Analogous to Template::SetLazyDataProperty.
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> SetLazyDataProperty(
      Local<Context> context, Local<Name> name,
      AccessorNameGetterCallback getter, Local<Value> data = Local<Value>(),
      PropertyAttribute attributes = None,
      SideEffectType getter_side_effect_type = SideEffectType::kHasSideEffect,
      SideEffectType setter_side_effect_type = SideEffectType::kHasSideEffect);

  /**
   * Functionality for private properties.
   * This is an experimental feature, use at your own risk.
   * Note: Private properties are not inherited. Do not rely on this, since it
   * may change.
   */
  Maybe<bool> HasPrivate(Local<Context> context, Local<Private> key);
  Maybe<bool> SetPrivate(Local<Context> context, Local<Private> key,
                         Local<Value> value);
  Maybe<bool> DeletePrivate(Local<Context> context, Local<Private> key);
  MaybeLocal<Value> GetPrivate(Local<Context> context, Local<Private> key);

  /**
   * Returns an array containing the names of the enumerable properties
   * of this object, including properties from prototype objects.  The
   * array returned by this method contains the same values as would
   * be enumerated by a for-in statement over this object.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Array> GetPropertyNames(
      Local<Context> context);
  V8_WARN_UNUSED_RESULT MaybeLocal<Array> GetPropertyNames(
      Local<Context> context, KeyCollectionMode mode,
      PropertyFilter property_filter, IndexFilter index_filter,
      KeyConversionMode key_conversion = KeyConversionMode::kKeepNumbers);

  /**
   * This function has the same functionality as GetPropertyNames but
   * the returned array doesn't contain the names of properties from
   * prototype objects.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Array> GetOwnPropertyNames(
      Local<Context> context);

  /**
   * Returns an array containing the names of the filtered properties
   * of this object, including properties from prototype objects.  The
   * array returned by this method contains the same values as would
   * be enumerated by a for-in statement over this object.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Array> GetOwnPropertyNames(
      Local<Context> context, PropertyFilter filter,
      KeyConversionMode key_conversion = KeyConversionMode::kKeepNumbers);

  /**
   * Get the prototype object.  This does not skip objects marked to
   * be skipped by __proto__ and it does not consult the security
   * handler.
   */
  V8_DEPRECATE_SOON(
      "V8 will stop providing access to hidden prototype (i.e. "
      "JSGlobalObject). Use GetPrototypeV2() instead. "
      "See http://crbug.com/333672197.")
  Local<Value> GetPrototype();

  /**
   * Get the prototype object (same as getting __proto__ property).  This does
   * not consult the security handler.
   * TODO(333672197): rename back to GetPrototype() once the old version goes
   * through the deprecation process and is removed.
   */
  Local<Value> GetPrototypeV2();

  /**
   * Set the prototype object.  This does not skip objects marked to
   * be skipped by __proto__ and it does not consult the security
   * handler.
   */
  V8_DEPRECATE_SOON(
      "V8 will stop providing access to hidden prototype (i.e. "
      "JSGlobalObject). Use SetPrototypeV2() instead. "
      "See http://crbug.com/333672197.")
  V8_WARN_UNUSED_RESULT Maybe<bool> SetPrototype(Local<Context> context,
                                                 Local<Value> prototype);

  /**
   * Set the prototype object (same as setting __proto__ property).  This does
   * does not consult the security handler.
   * TODO(333672197): rename back to SetPrototype() once the old version goes
   * through the deprecation process and is removed.
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> SetPrototypeV2(Local<Context> context,
                                                   Local<Value> prototype);

  /**
   * Finds an instance of the given function template in the prototype
   * chain.
   */
  Local<Object> FindInstanceInPrototypeChain(Local<FunctionTemplate> tmpl);

  /**
   * Call builtin Object.prototype.toString on this object.
   * This is different from Value::ToString() that may call
   * user-defined toString function. This one does not.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<String> ObjectProtoToString(
      Local<Context> context);

  /**
   * Returns the name of the function invoked as a constructor for this object.
   */
  Local<String> GetConstructorName();

  /**
   * Sets the integrity level of the object.
   */
  Maybe<bool> SetIntegrityLevel(Local<Context> context, IntegrityLevel level);

  /** Gets the number of internal fields for this Object. */
  int InternalFieldCount() const;

  /** Same as above, but works for PersistentBase. */
  V8_INLINE static int InternalFieldCount(
      const PersistentBase<Object>& object) {
    return object.template value<Object>()->InternalFieldCount();
  }

  /** Same as above, but works for BasicTracedReference. */
  V8_INLINE static int InternalFieldCount(
      const BasicTracedReference<Object>& object) {
    return object.template value<Object>()->InternalFieldCount();
  }

  /**
   * Gets the data from an internal field.
   * To cast the return value into v8::Value subtypes, it needs to be
   * casted to a v8::Value first. For example, to cast it into v8::External:
   *
   * object->GetInternalField(index).As<v8::Value>().As<v8::External>();
   *
   * The embedder should make sure that the internal field being retrieved
   * using this method has already been set with SetInternalField() before.
   **/
  V8_INLINE Local<Data> GetInternalField(int index);

  /** Sets the data in an internal field. */
  void SetInternalField(int index, Local<Data> data);

  /**
   * Gets a 2-byte-aligned native pointer from an internal field. This field
   * must have been set by SetAlignedPointerInInternalField, everything else
   * leads to undefined behavior.
   */
  V8_INLINE void* GetAlignedPointerFromInternalField(int index);
  V8_INLINE void* GetAlignedPointerFromInternalField(v8::Isolate* isolate,
                                                     int index);

  /** Same as above, but works for PersistentBase. */
  V8_INLINE static void* GetAlignedPointerFromInternalField(
      const PersistentBase<Object>& object, int index) {
    return object.template value<Object>()->GetAlignedPointerFromInternalField(
        index);
  }

  /** Same as above, but works for TracedReference. */
  V8_INLINE static void* GetAlignedPointerFromInternalField(
      const BasicTracedReference<Object>& object, int index) {
    return object.template value<Object>()->GetAlignedPointerFromInternalField(
        index);
  }

  /**
   * Sets a 2-byte-aligned native pointer in an internal field. To retrieve such
   * a field, GetAlignedPointerFromInternalField must be used, everything else
   * leads to undefined behavior.
   */
  void SetAlignedPointerInInternalField(int index, void* value);
  void SetAlignedPointerInInternalFields(int argc, int indices[],
                                         void* values[]);

  /**
   * Unwraps a JS wrapper object.
   *
   * \param tag The tag for retrieving the wrappable instance. Must match the
   * tag that has been used for a previous `Wrap()` operation.
   * \param isolate The Isolate for the `wrapper` object.
   * \param wrapper The JS wrapper object that should be unwrapped.
   * \returns the C++ wrappable instance, or nullptr if the JS object has never
   * been wrapped.
   */
  template <CppHeapPointerTag tag, typename T = void>
  static V8_INLINE T* Unwrap(v8::Isolate* isolate,
                             const v8::Local<v8::Object>& wrapper);
  template <CppHeapPointerTag tag, typename T = void>
  static V8_INLINE T* Unwrap(v8::Isolate* isolate,
                             const PersistentBase<Object>& wrapper);
  template <CppHeapPointerTag tag, typename T = void>
  static V8_INLINE T* Unwrap(v8::Isolate* isolate,
                             const BasicTracedReference<Object>& wrapper);

  template <typename T = void>
  static V8_INLINE T* Unwrap(v8::Isolate* isolate,
                             const v8::Local<v8::Object>& wrapper,
                             CppHeapPointerTagRange tag_range);
  template <typename T = void>
  static V8_INLINE T* Unwrap(v8::Isolate* isolate,
                             const PersistentBase<Object>& wrapper,
                             CppHeapPointerTagRange tag_range);
  template <typename T = void>
  static V8_INLINE T* Unwrap(v8::Isolate* isolate,
                             const BasicTracedReference<Object>& wrapper,
                             CppHeapPointerTagRange tag_range);

  /**
   * Wraps a JS wrapper with a C++ instance.
   *
   * \param tag The pointer tag that should be used for storing this object.
   * Future `Unwrap()` operations must provide a matching tag.
   * \param isolate The Isolate for the `wrapper` object.
   * \param wrapper The JS wrapper object.
   * \param wrappable The C++ object instance that is wrapped by the JS object.
   */
  template <CppHeapPointerTag tag>
  static V8_INLINE void Wrap(v8::Isolate* isolate,
                             const v8::Local<v8::Object>& wrapper,
                             void* wrappable);
  template <CppHeapPointerTag tag>
  static V8_INLINE void Wrap(v8::Isolate* isolate,
                             const PersistentBase<Object>& wrapper,
                             void* wrappable);
  template <CppHeapPointerTag tag>
  static V8_INLINE void Wrap(v8::Isolate* isolate,
                             const BasicTracedReference<Object>& wrapper,
                             void* wrappable);
  static V8_INLINE void Wrap(v8::Isolate* isolate,
                             const v8::Local<v8::Object>& wrapper,
                             void* wrappable, CppHeapPointerTag tag);
  static V8_INLINE void Wrap(v8::Isolate* isolate,
                             const PersistentBase<Object>& wrapper,
                             void* wrappable, CppHeapPointerTag tag);
  static V8_INLINE void Wrap(v8::Isolate* isolate,
                             const BasicTracedReference<Object>& wrapper,
                             void* wrappable, CppHeapPointerTag tag);

  /**
   * HasOwnProperty() is like JavaScript's
   * Object.prototype.hasOwnProperty().
   *
   * See also v8::Object::Has() and v8::Object::HasRealNamedProperty().
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> HasOwnProperty(Local<Context> context,
                                                   Local<Name> key);
  V8_WARN_UNUSED_RESULT Maybe<bool> HasOwnProperty(Local<Context> context,
                                                   uint32_t index);
  /**
   * Use HasRealNamedProperty() if you want to check if an object has an own
   * property without causing side effects, i.e., without calling interceptors.
   *
   * This function is similar to v8::Object::HasOwnProperty(), but it does not
   * call interceptors.
   *
   * \note Consider using non-masking interceptors, i.e., the interceptors are
   * not called if the receiver has the real named property. See
   * `v8::PropertyHandlerFlags::kNonMasking`.
   *
   * See also v8::Object::Has().
   */
  V8_WARN_UNUSED_RESULT Maybe<bool> HasRealNamedProperty(Local<Context> context,
                                                         Local<Name> key);
  V8_WARN_UNUSED_RESULT Maybe<bool> HasRealIndexedProperty(
      Local<Context> context, uint32_t index);
  V8_WARN_UNUSED_RESULT Maybe<bool> HasRealNamedCallbackProperty(
      Local<Context> context, Local<Name> key);

  /**
   * If result.IsEmpty() no real property was located in the prototype chain.
   * This means interceptors in the prototype chain are not called.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Value> GetRealNamedPropertyInPrototypeChain(
      Local<Context> context, Local<Name> key);

  /**
   * Gets the property attributes of a real property in the prototype chain,
   * which can be None or any combination of ReadOnly, DontEnum and DontDelete.
   * Interceptors in the prototype chain are not called.
   */
  V8_WARN_UNUSED_RESULT Maybe<PropertyAttribute>
  GetRealNamedPropertyAttributesInPrototypeChain(Local<Context> context,
                                                 Local<Name> key);

  /**
   * If result.IsEmpty() no real property was located on the object or
   * in the prototype chain.
   * This means interceptors in the prototype chain are not called.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Value> GetRealNamedProperty(
      Local<Context> context, Local<Name> key);

  /**
   * Gets the property attributes of a real property which can be
   * None or any combination of ReadOnly, DontEnum and DontDelete.
   * Interceptors in the prototype chain are not called.
   */
  V8_WARN_UNUSED_RESULT Maybe<PropertyAttribute> GetRealNamedPropertyAttributes(
      Local<Context> context, Local<Name> key);

  /** Tests for a named lookup interceptor.*/
  bool HasNamedLookupInterceptor() const;

  /** Tests for an index lookup interceptor.*/
  bool HasIndexedLookupInterceptor() const;

  /**
   * Returns the identity hash for this object. The current implementation
   * uses a hidden property on the object to store the identity hash.
   *
   * The return value will never be 0. Also, it is not guaranteed to be
   * unique.
   */
  int GetIdentityHash();

  /**
   * Clone this object with a fast but shallow copy. Values will point to the
   * same values as the original object.
   *
   * Prefer using version with Isolate parameter.
   */
  Local<Object> Clone(v8::Isolate* isolate);
  Local<Object> Clone();

  /**
   * Returns the context in which the object was created.
   *
   * Prefer using version with Isolate parameter.
   */
  MaybeLocal<Context> GetCreationContext(v8::Isolate* isolate);
  V8_DEPRECATE_SOON("Use the version with the isolate argument.")
  MaybeLocal<Context> GetCreationContext();

  /**
   * Shortcut for GetCreationContext(...).ToLocalChecked().
   *
   * Prefer using version with Isolate parameter.
   **/
  Local<Context> GetCreationContextChecked(v8::Isolate* isolate);
  V8_DEPRECATE_SOON("Use the version with the isolate argument.")
  Local<Context> GetCreationContextChecked();

  /** Same as above, but works for Persistents */
  V8_INLINE static MaybeLocal<Context> GetCreationContext(
      v8::Isolate* isolate, const PersistentBase<Object>& object) {
    return object.template value<Object>()->GetCreationContext(isolate);
  }
  V8_DEPRECATE_SOON("Use the version with the isolate argument.")
  V8_INLINE static MaybeLocal<Context> GetCreationContext(
      const PersistentBase<Object>& object);

  /**
   * Gets the context in which the object was created (see GetCreationContext())
   * and if it's available reads respective embedder field value.
   * If the context can't be obtained nullptr is returned.
   * Basically it's a shortcut for
   *   obj->GetCreationContext().GetAlignedPointerFromEmbedderData(index)
   * which doesn't create a handle for Context object on the way and doesn't
   * try to expand the embedder data attached to the context.
   * In case the Local<Context> is already available because of other reasons,
   * it's fine to keep using Context::GetAlignedPointerFromEmbedderData().
   *
   * Prefer using version with Isolate parameter if you have an Isolate,
   * otherwise use the other one.
   */
  void* GetAlignedPointerFromEmbedderDataInCreationContext(v8::Isolate* isolate,
                                                           int index);
  void* GetAlignedPointerFromEmbedderDataInCreationContext(int index);

  /**
   * Checks whether a callback is set by the
   * ObjectTemplate::SetCallAsFunctionHandler method.
   * When an Object is callable this method returns true.
   */
  bool IsCallable() const;

  /**
   * True if this object is a constructor.
   */
  bool IsConstructor() const;

  /**
   * Returns true if this object can be generally used to wrap object objects.
   * This means that the object either follows the convention of using embedder
   * fields to denote type/instance pointers or is using the Wrap()/Unwrap()
   * APIs for the same purpose. Returns false otherwise.
   *
   * Note that there may be other objects that use embedder fields but are not
   * used as API wrapper objects. E.g., v8::Promise may in certain configuration
   * use embedder fields but promises are not generally supported as API
   * wrappers. The method will return false in those cases.
   */
  bool IsApiWrapper() const;

  /**
   * True if this object was created from an object template which was marked
   * as undetectable. See v8::ObjectTemplate::MarkAsUndetectable for more
   * information.
   */
  bool IsUndetectable() const;

  /**
   * Call an Object as a function if a callback is set by the
   * ObjectTemplate::SetCallAsFunctionHandler method.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Value> CallAsFunction(Local<Context> context,
                                                         Local<Value> recv,
                                                         int argc,
                                                         Local<Value> argv[]);

  /**
   * Call an Object as a constructor if a callback is set by the
   * ObjectTemplate::SetCallAsFunctionHandler method.
   * Note: This method behaves like the Function::NewInstance method.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Value> CallAsConstructor(
      Local<Context> context, int argc, Local<Value> argv[]);

  /**
   * Return the isolate to which the Object belongs to.
   */
  Isolate* GetIsolate();

  V8_INLINE static Isolate* GetIsolate(const TracedReference<Object>& handle) {
    return handle.template value<Object>()->GetIsolate();
  }

  /**
   * If this object is a Set, Map, WeakSet or WeakMap, this returns a
   * representation of the elements of this object as an array.
   * If this object is a SetIterator or MapIterator, this returns all
   * elements of the underlying collection, starting at the iterator's current
   * position.
   * For other types, this will return an empty MaybeLocal<Array> (without
   * scheduling an exception).
   */
  MaybeLocal<Array> PreviewEntries(bool* is_key_value);

  static Local<Object> New(Isolate* isolate);

  /**
   * Creates a JavaScript object with the given properties, and
   * a the given prototype_or_null (which can be any JavaScript
   * value, and if it's null, the newly created object won't have
   * a prototype at all). This is similar to Object.create().
   * All properties will be created as enumerable, configurable
   * and writable properties.
   */
  static Local<Object> New(Isolate* isolate, Local<Value> prototype_or_null,
                           Local<Name>* names, Local<Value>* values,
                           size_t length);

  V8_INLINE static Object* Cast(Value* obj);

  /**
   * Support for TC39 "dynamic code brand checks" proposal.
   *
   * This API allows to query whether an object was constructed from a
   * "code like" ObjectTemplate.
   *
   * See also: v8::ObjectTemplate::SetCodeLike
   */
  bool IsCodeLike(Isolate* isolate) const;

 private:
  static void* Unwrap(v8::Isolate* isolate, internal::Address wrapper_obj,
                      CppHeapPointerTagRange tag_range);
  static void Wrap(v8::Isolate* isolate, internal::Address wrapper_obj,
                   CppHeapPointerTag tag, void* wrappable);

  Object();
  static void CheckCast(Value* obj);
  Local<Data> SlowGetInternalField(int index);
  void* SlowGetAlignedPointerFromInternalField(int index);
  void* SlowGetAlignedPointerFromInternalField(v8::Isolate* isolate, int index);
};

// --- Implementation ---

Local<Data> Object::GetInternalField(int inde
"""


```