Response:
The user wants to understand the functionality of the C++ header file `v8/src/objects/js-objects.h`. I need to analyze the provided code snippet and explain its purpose within the V8 JavaScript engine.

Here's a breakdown of the information I need to extract and present:

1. **Core Functionality:**  What is the primary role of this header file? What kinds of objects and operations does it define?
2. **Torque Connection:** Does the presence of `#include "torque-generated/src/objects/js-objects-tq.inc"` indicate this file is related to Torque?
3. **JavaScript Relevance:** How do the concepts in this C++ file relate to JavaScript features and behavior? Provide JavaScript examples.
4. **Code Logic Inference:** Are there any functions or methods where I can infer the logic based on their names and parameters? Provide hypothetical inputs and outputs.
5. **Common Programming Errors:**  Does this file's content suggest any typical mistakes JavaScript developers might make?
6. **Summary:** Concisely summarize the overall function of the header file.
```
这是目录为v8/src/objects/js-objects.h的一个v8源代码， 请列举一下它的功能,
如果v8/src/objects/js-objects.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

根据提供的代码片段，`v8/src/objects/js-objects.h` 是一个 C++ 头文件，它在 V8 JavaScript 引擎中定义了用于表示 JavaScript 对象的类和相关功能。

**功能归纳:**

1. **定义 JavaScript 对象的核心结构:**  它定义了 `JSReceiver` 和 `JSObject` 这两个核心类，它们是所有可以拥有属性的 JavaScript 值的基类。`JSReceiver` 是一个抽象基类，代表可以定义属性的实体 (包括普通对象和代理对象)，而 `JSObject` 代表了实际的堆分配的 JavaScript 对象。

2. **属性操作:** 提供了大量的方法用于操作 JavaScript 对象的属性，包括：
   - **获取属性:** `GetProperty`, `GetElement`, `GetDataProperty`, `GetOwnPropertyDescriptor`, `GetOwnPropertyAttributes` 等。
   - **设置属性:** `DefineProperty`, `DefineOwnProperty`, `CreateDataProperty`, `SetOwnPropertyIgnoreAttributes`, `SetOwnElementIgnoreAttributes`, `AddProperty`, `AddDataElement` 等。
   - **删除属性:** `DeleteProperty`, `DeleteElement`.
   - **检查属性:** `HasProperty`, `HasOwnProperty`, `HasElement`.
   - **枚举属性:** `OwnPropertyKeys`, `GetOwnValues`, `GetOwnEntries`.

3. **原型链管理:**  定义了与原型链交互的方法，例如 `GetPrototype`, `HasInPrototypeChain`, `SetPrototype`, `GetConstructor`, `GetConstructorName`, `MakePrototypesFast`.

4. **对象元信息管理:**  包含了管理对象内部状态的方法，例如：
   - **属性存储:**  管理快速属性 (`PropertyArray`) 和慢速属性 (`NameDictionary`, `SwissNameDictionary`) 的存储和切换。
   - **元素存储:** 管理不同类型的元素存储 (`FixedArray`, `NumberDictionary`)，包括 Packed 和 Holey 模式，以及 Smi 和 Double 类型的优化。
   - **可扩展性:** `PreventExtensions`, `IsExtensible`, `SetIntegrityLevel`, `TestIntegrityLevel`.
   - **哈希值:** `GetIdentityHash`, `CreateIdentityHash`, `GetOrCreateIdentityHash`, `SetIdentityHash` 用于对象身份标识。
   - **Map 管理:**  与对象的 Map（描述对象结构和类型的元数据）相关的方法，例如 `MigrateInstance`, `TryMigrateInstance`, `TransitionElementsKind`, `MigrateToMap`.

5. **与拦截器交互:**  定义了与属性访问拦截器 (`InterceptorInfo`) 交互的方法，用于处理由宿主对象控制的属性。

6. **类型判断:**  提供了判断对象元素类型的方法，例如 `HasSmiElements`, `HasObjectElements`, `HasDoubleElements`, `HasDictionaryElements` 等。

7. **与其他 V8 内部组件交互:**  涉及到与其他 V8 内部组件的交互，例如 `LookupIterator`（用于属性查找），`AllocationSite`（用于内联缓存）。

**关于 Torque 源代码:**

代码中包含 `#include "torque-generated/src/objects/js-objects-tq.inc"`. 这表明 `v8/src/objects/js-objects.h` 确实与 V8 的 Torque 编译系统有关。以 `.tq` 结尾的文件是 Torque 的源代码，Torque 是一种用于生成 V8 运行时代码的领域特定语言。`.inc` 文件通常是被包含到其他文件中的代码片段。因此，`js-objects-tq.inc` 很可能是由 Torque 编译生成的 C++ 代码，其中包含了与 `JSReceiver` 和 `JSObject` 类定义相关的辅助代码或优化实现。

**与 JavaScript 功能的关系及示例:**

这个头文件中定义的类和方法直接对应着 JavaScript 语言的各种对象操作行为。

* **创建对象和访问属性:**

   ```javascript
   const obj = { a: 1, b: 2 };
   console.log(obj.a); // 对应 C++ 中的 GetProperty 等方法
   obj.c = 3;          // 对应 C++ 中的 DefineProperty, CreateDataProperty 等方法
   delete obj.b;       // 对应 C++ 中的 DeleteProperty 方法
   ```

* **原型链:**

   ```javascript
   function Animal(name) {
     this.name = name;
   }
   Animal.prototype.sayHello = function() {
     console.log(`Hello, I'm ${this.name}`);
   };

   const dog = new Animal("Buddy");
   dog.sayHello(); // 原型链查找，对应 C++ 中的 GetPrototype, HasInPrototypeChain 等方法
   ```

* **属性描述符:**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'x', {
     value: 42,
     writable: false,
     enumerable: true,
     configurable: false
   }); // 对应 C++ 中的 DefineOwnProperty 和 PropertyDescriptor 相关操作
   ```

* **不可扩展对象和冻结对象:**

   ```javascript
   const obj1 = { a: 1 };
   Object.preventExtensions(obj1); // 对应 C++ 中的 PreventExtensions 方法

   const obj2 = { b: 2 };
   Object.freeze(obj2);          // 对应 C++ 中的 SetIntegrityLevel 方法
   ```

* **数组的元素操作:**

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[0]); // 对应 C++ 中对元素存储的访问
   arr.push(4);       // 对应 C++ 中元素存储的扩展和写入
   ```

**代码逻辑推理示例:**

考虑 `SetOrCopyDataProperties` 方法：

**假设输入:**

- `target`: 一个空的 JavaScript 对象 `{}`
- `source`: 一个 JavaScript 对象 `{ a: 1, b: 2 }`
- `mode`:  某种枚举模式，例如只复制可枚举属性
- `excluded_properties`: 空列表
- `use_set`: `true`

**预期输出:**

`target` 对象变为 `{ a: 1, b: 2 }`，函数返回 `Maybe<bool>`，指示操作是否成功（在本例中应为成功）。

**用户常见的编程错误示例:**

* **尝试给不可扩展对象添加属性:**

   ```javascript
   const obj = {};
   Object.preventExtensions(obj);
   obj.newProp = 5; // TypeError: Cannot add property newProp, object is not extensible
   ```
   这对应于 V8 内部 `PreventExtensions` 相关的检查。

* **试图删除不可配置的属性:**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'x', { configurable: false, value: 10 });
   delete obj.x; // 在严格模式下抛出 TypeError，在非严格模式下静默失败，对应 C++ 中的 DeleteProperty 检查 configurable 属性。
   ```

* **误解原型链导致属性查找失败:**

   ```javascript
   function Parent() {}
   Parent.prototype.value = 10;
   function Child() {}
   Child.prototype = new Parent();
   const child = new Child();
   console.log(child.value); // 输出 10，依赖于 V8 的原型链查找机制
   console.log(child.hasOwnProperty('value')); // 输出 false，因为 value 属性在原型上
   ```

**总结 (第 1 部分):**

`v8/src/objects/js-objects.h` 是 V8 引擎中至关重要的头文件，它定义了 JavaScript 对象在 C++ 层的表示和操作方式。它包含了 `JSReceiver` 和 `JSObject` 类及其丰富的成员方法，用于实现 JavaScript 语言中关于对象创建、属性访问、修改、删除、原型链管理、元数据管理等核心功能。该文件与 V8 的 Torque 编译系统相关联，并直接影响着 JavaScript 代码的执行行为。理解这个文件的内容有助于深入了解 V8 引擎的内部工作原理。

### 提示词
```
这是目录为v8/src/objects/js-objects.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_JS_OBJECTS_H_
#define V8_OBJECTS_JS_OBJECTS_H_

#include <optional>

#include "src/common/globals.h"
#include "src/handles/handles.h"
#include "src/objects/embedder-data-slot.h"
// TODO(jkummerow): Consider forward-declaring instead.
#include "src/objects/internal-index.h"
#include "src/objects/objects.h"
#include "src/objects/property-array.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

// Enum for functions that offer a second mode that does not cause allocations.
// Used in conjunction with LookupIterator and unboxed double fields.
enum class AllocationPolicy { kAllocationAllowed, kAllocationDisallowed };

enum InstanceType : uint16_t;
class JSGlobalObject;
class JSGlobalProxy;
class LookupIterator;
class PropertyDescriptor;
class PropertyKey;
class NativeContext;
class IsCompiledScope;
class StackTraceInfo;
class SwissNameDictionary;
class ElementsAccessor;
class Undefined;
class Null;

#include "torque-generated/src/objects/js-objects-tq.inc"

// JSReceiver includes types on which properties can be defined, i.e.,
// JSObject and JSProxy.
class JSReceiver : public TorqueGeneratedJSReceiver<JSReceiver, HeapObject> {
 public:
  NEVER_READ_ONLY_SPACE
  // Returns true if there is no slow (ie, dictionary) backing store.
  DECL_GETTER(HasFastProperties, bool)

  // Returns the properties array backing store if it
  // exists. Otherwise, returns an empty_property_array when there's a
  // Smi (hash code) or an empty_fixed_array for a fast properties
  // map.
  DECL_GETTER(property_array, Tagged<PropertyArray>)

  // Gets slow properties for non-global objects (if
  // v8_enable_swiss_name_dictionary is not set).
  DECL_GETTER(property_dictionary, Tagged<NameDictionary>)

  // Gets slow properties for non-global objects (if
  // v8_enable_swiss_name_dictionary is set).
  DECL_GETTER(property_dictionary_swiss, Tagged<SwissNameDictionary>)

  // Sets the properties backing store and makes sure any existing hash is moved
  // to the new properties store. To clear out the properties store, pass in the
  // empty_fixed_array(), the hash will be maintained in this case as well.
  void SetProperties(Tagged<HeapObject> properties);

  // There are five possible values for the properties offset.
  // 1) EmptyFixedArray/EmptyPropertyDictionary - This is the standard
  // placeholder.
  //
  // 2) Smi - This is the hash code of the object.
  //
  // 3) PropertyArray - This is similar to a FixedArray but stores
  // the hash code of the object in its length field. This is a fast
  // backing store.
  //
  // 4) NameDictionary - This is the dictionary-mode backing store.
  //
  // 4) GlobalDictionary - This is the backing store for the
  // GlobalObject.
  //
  // This is used only in the deoptimizer and heap. Please use the
  // above typed getters and setters to access the properties.
  DECL_ACCESSORS(raw_properties_or_hash, Tagged<Object>)
  DECL_RELAXED_ACCESSORS(raw_properties_or_hash, Tagged<Object>)

  inline void initialize_properties(Isolate* isolate);

  // Deletes an existing named property in a normalized object.
  static void DeleteNormalizedProperty(DirectHandle<JSReceiver> object,
                                       InternalIndex entry);

  // ES6 section 7.1.1 ToPrimitive
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> ToPrimitive(
      Isolate* isolate, Handle<JSReceiver> receiver,
      ToPrimitiveHint hint = ToPrimitiveHint::kDefault);

  // ES6 section 7.1.1.1 OrdinaryToPrimitive
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> OrdinaryToPrimitive(
      Isolate* isolate, Handle<JSReceiver> receiver,
      OrdinaryToPrimitiveHint hint);

  // Unwraps the chain of potential function wrappers or JSProxy objects and
  // return the leaf function's creation context.
  // Throws TypeError in case there's a revoked JSProxy on the way.
  // https://tc39.es/ecma262/#sec-getfunctionrealm
  static MaybeHandle<NativeContext> GetFunctionRealm(
      DirectHandle<JSReceiver> receiver);

  V8_EXPORT_PRIVATE static MaybeHandle<NativeContext> GetContextForMicrotask(
      DirectHandle<JSReceiver> receiver);

  // Get the first non-hidden prototype.
  static inline MaybeHandle<JSPrototype> GetPrototype(
      Isolate* isolate, Handle<JSReceiver> receiver);

  V8_WARN_UNUSED_RESULT static Maybe<bool> HasInPrototypeChain(
      Isolate* isolate, Handle<JSReceiver> object, Handle<Object> proto);

  // Reads all enumerable own properties of source and adds them to
  // target, using either Set or CreateDataProperty depending on the
  // use_set argument. This only copies values not present in the
  // maybe_excluded_properties list.
  // If direct handles are enabled, it is the responsibility of the caller to
  // ensure that the memory pointed to by `excluded_properties` is scanned
  // during CSS, e.g., it comes from a `DirectHandleVector<Object>`.
  V8_WARN_UNUSED_RESULT static Maybe<bool> SetOrCopyDataProperties(
      Isolate* isolate, Handle<JSReceiver> target, Handle<Object> source,
      PropertiesEnumerationMode mode,
      base::Vector<DirectHandle<Object>> excluded_properties = {},
      bool use_set = true);

  // Implementation of [[HasProperty]], ECMA-262 5th edition, section 8.12.6.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool> HasProperty(
      LookupIterator* it);
  V8_WARN_UNUSED_RESULT static inline Maybe<bool> HasProperty(
      Isolate* isolate, Handle<JSReceiver> object, Handle<Name> name);
  V8_WARN_UNUSED_RESULT static inline Maybe<bool> HasElement(
      Isolate* isolate, Handle<JSReceiver> object, uint32_t index);

  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool> HasOwnProperty(
      Isolate* isolate, Handle<JSReceiver> object, Handle<Name> name);
  V8_WARN_UNUSED_RESULT static inline Maybe<bool> HasOwnProperty(
      Isolate* isolate, Handle<JSReceiver> object, uint32_t index);

  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> GetProperty(
      Isolate* isolate, Handle<JSReceiver> receiver, const char* key);
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> GetProperty(
      Isolate* isolate, Handle<JSReceiver> receiver, Handle<Name> name);
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> GetElement(
      Isolate* isolate, Handle<JSReceiver> receiver, uint32_t index);

  // Implementation of ES6 [[Delete]]
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool>
  DeletePropertyOrElement(Isolate* isolate, Handle<JSReceiver> object,
                          Handle<Name> name,
                          LanguageMode language_mode = LanguageMode::kSloppy);
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool> DeleteProperty(
      Isolate* isolate, Handle<JSReceiver> object, Handle<Name> name,
      LanguageMode language_mode = LanguageMode::kSloppy);
  V8_WARN_UNUSED_RESULT static Maybe<bool> DeleteProperty(
      LookupIterator* it, LanguageMode language_mode);
  V8_WARN_UNUSED_RESULT static Maybe<bool> DeleteElement(
      Isolate* isolate, Handle<JSReceiver> object, uint32_t index,
      LanguageMode language_mode = LanguageMode::kSloppy);

  V8_WARN_UNUSED_RESULT static Tagged<Object> DefineProperty(
      Isolate* isolate, Handle<Object> object, Handle<Object> name,
      Handle<Object> attributes);
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> DefineProperties(
      Isolate* isolate, Handle<Object> object, Handle<Object> properties);

  // "virtual" dispatcher to the correct [[DefineOwnProperty]] implementation.
  V8_WARN_UNUSED_RESULT static Maybe<bool> DefineOwnProperty(
      Isolate* isolate, Handle<JSReceiver> object, Handle<Object> key,
      PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw);

  // Check if private name property can be store on the object. It will return
  // false with an error when it cannot but didn't throw, or a Nothing if
  // it throws.
  V8_WARN_UNUSED_RESULT static Maybe<bool> CheckPrivateNameStore(
      LookupIterator* it, bool is_define);

  // ES6 7.3.4 (when passed kDontThrow)
  V8_WARN_UNUSED_RESULT static Maybe<bool> CreateDataProperty(
      Isolate* isolate, Handle<JSReceiver> object, Handle<Name> key,
      Handle<Object> value, Maybe<ShouldThrow> should_throw);
  V8_WARN_UNUSED_RESULT static Maybe<bool> CreateDataProperty(
      Isolate* isolate, Handle<JSAny> object, PropertyKey key,
      Handle<Object> value, Maybe<ShouldThrow> should_throw);
  V8_WARN_UNUSED_RESULT static Maybe<bool> CreateDataProperty(
      Isolate* isolate, Handle<JSReceiver> object, PropertyKey key,
      Handle<Object> value, Maybe<ShouldThrow> should_throw);

  // Add private fields to the receiver, ignoring extensibility and the
  // traps. The caller should check that the private field does not already
  // exist on the receiver before calling this method.
  V8_WARN_UNUSED_RESULT static Maybe<bool> AddPrivateField(
      LookupIterator* it, Handle<Object> value,
      Maybe<ShouldThrow> should_throw);

  // ES6 9.1.6.1
  V8_WARN_UNUSED_RESULT static Maybe<bool> OrdinaryDefineOwnProperty(
      Isolate* isolate, Handle<JSObject> object, Handle<Object> key,
      PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw);
  V8_WARN_UNUSED_RESULT static Maybe<bool> OrdinaryDefineOwnProperty(
      Isolate* isolate, Handle<JSObject> object, const PropertyKey& key,
      PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw);
  V8_WARN_UNUSED_RESULT static Maybe<bool> OrdinaryDefineOwnProperty(
      LookupIterator* it, PropertyDescriptor* desc,
      Maybe<ShouldThrow> should_throw);
  // ES6 9.1.6.2
  V8_WARN_UNUSED_RESULT static Maybe<bool> IsCompatiblePropertyDescriptor(
      Isolate* isolate, bool extensible, PropertyDescriptor* desc,
      PropertyDescriptor* current, Handle<Name> property_name,
      Maybe<ShouldThrow> should_throw);
  // ES6 9.1.6.3
  // |it| can be NULL in cases where the ES spec passes |undefined| as the
  // receiver. Exactly one of |it| and |property_name| must be provided.
  V8_WARN_UNUSED_RESULT static Maybe<bool> ValidateAndApplyPropertyDescriptor(
      Isolate* isolate, LookupIterator* it, bool extensible,
      PropertyDescriptor* desc, PropertyDescriptor* current,
      Maybe<ShouldThrow> should_throw, Handle<Name> property_name);

  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool>
  GetOwnPropertyDescriptor(Isolate* isolate, Handle<JSReceiver> object,
                           Handle<Object> key, PropertyDescriptor* desc);
  V8_WARN_UNUSED_RESULT static Maybe<bool> GetOwnPropertyDescriptor(
      LookupIterator* it, PropertyDescriptor* desc);

  using IntegrityLevel = PropertyAttributes;

  // ES6 7.3.14 (when passed kDontThrow)
  // 'level' must be SEALED or FROZEN.
  V8_WARN_UNUSED_RESULT static Maybe<bool> SetIntegrityLevel(
      Isolate* isolate, Handle<JSReceiver> object, IntegrityLevel lvl,
      ShouldThrow should_throw);

  // ES6 7.3.15
  // 'level' must be SEALED or FROZEN.
  V8_WARN_UNUSED_RESULT static Maybe<bool> TestIntegrityLevel(
      Isolate* isolate, Handle<JSReceiver> object, IntegrityLevel lvl);

  // ES6 [[PreventExtensions]] (when passed kDontThrow)
  V8_WARN_UNUSED_RESULT static Maybe<bool> PreventExtensions(
      Isolate* isolate, Handle<JSReceiver> object, ShouldThrow should_throw);

  V8_WARN_UNUSED_RESULT static Maybe<bool> IsExtensible(
      Isolate* isolate, Handle<JSReceiver> object);

  // Returns the class name.
  V8_EXPORT_PRIVATE Tagged<String> class_name();

  // Returns the constructor (the function that was used to instantiate the
  // object).
  static MaybeHandle<JSFunction> GetConstructor(Isolate* isolate,
                                                Handle<JSReceiver> receiver);

  // Returns the constructor name (the (possibly inferred) name of the function
  // that was used to instantiate the object), if any. If a FunctionTemplate is
  // used to instantiate the object, the class_name of the FunctionTemplate is
  // returned instead.
  static Handle<String> GetConstructorName(Isolate* isolate,
                                           Handle<JSReceiver> receiver);

  V8_EXPORT_PRIVATE inline std::optional<Tagged<NativeContext>>
  GetCreationContext();
  V8_EXPORT_PRIVATE inline MaybeHandle<NativeContext> GetCreationContext(
      Isolate* isolate);

  V8_WARN_UNUSED_RESULT static inline Maybe<PropertyAttributes>
  GetPropertyAttributes(Handle<JSReceiver> object, Handle<Name> name);
  V8_WARN_UNUSED_RESULT static inline Maybe<PropertyAttributes>
  GetOwnPropertyAttributes(Handle<JSReceiver> object, Handle<Name> name);
  V8_WARN_UNUSED_RESULT static inline Maybe<PropertyAttributes>
  GetOwnPropertyAttributes(Handle<JSReceiver> object, uint32_t index);

  V8_WARN_UNUSED_RESULT static inline Maybe<PropertyAttributes>
  GetElementAttributes(Handle<JSReceiver> object, uint32_t index);
  V8_WARN_UNUSED_RESULT static inline Maybe<PropertyAttributes>
  GetOwnElementAttributes(Handle<JSReceiver> object, uint32_t index);

  V8_WARN_UNUSED_RESULT static Maybe<PropertyAttributes> GetPropertyAttributes(
      LookupIterator* it);

  // Set the object's prototype (only JSReceiver and null are allowed values).
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool> SetPrototype(
      Isolate* isolate, Handle<JSReceiver> object, Handle<Object> value,
      bool from_javascript, ShouldThrow should_throw);

  inline static Handle<Object> GetDataProperty(Isolate* isolate,
                                               Handle<JSReceiver> object,
                                               Handle<Name> name);
  V8_EXPORT_PRIVATE static Handle<Object> GetDataProperty(
      LookupIterator* it, AllocationPolicy allocation_policy =
                              AllocationPolicy::kAllocationAllowed);

  // Retrieves a permanent object identity hash code. The undefined value might
  // be returned in case no hash was created yet.
  V8_EXPORT_PRIVATE Tagged<Object> GetIdentityHash();

  // Retrieves a permanent object identity hash code. May create and store a
  // hash code if needed and none exists.
  static Tagged<Smi> CreateIdentityHash(Isolate* isolate,
                                        Tagged<JSReceiver> key);
  V8_EXPORT_PRIVATE Tagged<Smi> GetOrCreateIdentityHash(Isolate* isolate);

  // Stores the hash code. The hash passed in must be masked with
  // JSReceiver::kHashMask.
  V8_EXPORT_PRIVATE void SetIdentityHash(int masked_hash);

  // ES6 [[OwnPropertyKeys]] (modulo return type)
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<FixedArray> OwnPropertyKeys(
      Isolate* isolate, Handle<JSReceiver> object);

  V8_WARN_UNUSED_RESULT static MaybeHandle<FixedArray> GetOwnValues(
      Isolate* isolate, Handle<JSReceiver> object, PropertyFilter filter,
      bool try_fast_path = true);

  V8_WARN_UNUSED_RESULT static MaybeHandle<FixedArray> GetOwnEntries(
      Isolate* isolate, Handle<JSReceiver> object, PropertyFilter filter,
      bool try_fast_path = true);

  static const int kHashMask = PropertyArray::HashField::kMask;

  bool HasProxyInPrototype(Isolate* isolate);

  // TC39 "Dynamic Code Brand Checks"
  bool IsCodeLike(Isolate* isolate) const;

 private:
  // Hide generated accessors; custom accessors are called
  // "raw_properties_or_hash".
  DECL_ACCESSORS(properties_or_hash, Tagged<Object>)

  TQ_OBJECT_CONSTRUCTORS(JSReceiver)
};

// The JSObject describes real heap allocated JavaScript objects with
// properties.
// Note that the map of JSObject changes during execution to enable inline
// caching.
class JSObject : public TorqueGeneratedJSObject<JSObject, JSReceiver> {
 public:
  static bool IsUnmodifiedApiObject(FullObjectSlot o);

  V8_EXPORT_PRIVATE static V8_WARN_UNUSED_RESULT MaybeHandle<JSObject> New(
      Handle<JSFunction> constructor, Handle<JSReceiver> new_target,
      DirectHandle<AllocationSite> site,
      NewJSObjectType = NewJSObjectType::kNoAPIWrapper);

  static MaybeHandle<JSObject> NewWithMap(
      Isolate* isolate, DirectHandle<Map> initial_map,
      DirectHandle<AllocationSite> site,
      NewJSObjectType = NewJSObjectType::kNoAPIWrapper);

  // 9.1.12 ObjectCreate ( proto [ , internalSlotsList ] )
  // Notice: This is NOT 19.1.2.2 Object.create ( O, Properties )
  static V8_WARN_UNUSED_RESULT MaybeHandle<JSObject> ObjectCreate(
      Isolate* isolate, Handle<JSPrototype> prototype);

  DECL_ACCESSORS(elements, Tagged<FixedArrayBase>)
  DECL_RELAXED_GETTER(elements, Tagged<FixedArrayBase>)

  // Acquire/release semantics on this field are explicitly forbidden to avoid
  // confusion, since the default setter uses relaxed semantics. If
  // acquire/release semantics ever become necessary, the default setter should
  // be reverted to non-atomic behavior, and setters with explicit tags
  // introduced and used when required.
  Tagged<FixedArrayBase> elements(PtrComprCageBase cage_base,
                                  AcquireLoadTag tag) const = delete;
  void set_elements(Tagged<FixedArrayBase> value, ReleaseStoreTag tag,
                    WriteBarrierMode mode = UPDATE_WRITE_BARRIER) = delete;

  inline void initialize_elements();
  static inline void SetMapAndElements(DirectHandle<JSObject> object,
                                       DirectHandle<Map> map,
                                       DirectHandle<FixedArrayBase> elements);
  DECL_GETTER(GetElementsKind, ElementsKind)
  DECL_GETTER(GetElementsAccessor, ElementsAccessor*)

  // Returns true if an object has elements of PACKED_SMI_ELEMENTS or
  // HOLEY_SMI_ELEMENTS ElementsKind.
  DECL_GETTER(HasSmiElements, bool)
  // Returns true if an object has elements of PACKED_ELEMENTS or
  // HOLEY_ELEMENTS ElementsKind.
  DECL_GETTER(HasObjectElements, bool)
  // Returns true if an object has elements of PACKED_SMI_ELEMENTS,
  // HOLEY_SMI_ELEMENTS, PACKED_ELEMENTS, or HOLEY_ELEMENTS.
  DECL_GETTER(HasSmiOrObjectElements, bool)
  // Returns true if an object has any of the "fast" elements kinds.
  DECL_GETTER(HasFastElements, bool)
  // Returns true if an object has any of the PACKED elements kinds.
  DECL_GETTER(HasFastPackedElements, bool)
  // Returns true if an object has elements of PACKED_DOUBLE_ELEMENTS or
  // HOLEY_DOUBLE_ELEMENTS ElementsKind.
  DECL_GETTER(HasDoubleElements, bool)
  // Returns true if an object has elements of HOLEY_SMI_ELEMENTS,
  // HOLEY_DOUBLE_ELEMENTS, or HOLEY_ELEMENTS ElementsKind.
  DECL_GETTER(HasHoleyElements, bool)
  DECL_GETTER(HasSloppyArgumentsElements, bool)
  DECL_GETTER(HasStringWrapperElements, bool)
  DECL_GETTER(HasDictionaryElements, bool)

  // Returns true if an object has elements of PACKED_ELEMENTS
  DECL_GETTER(HasPackedElements, bool)
  DECL_GETTER(HasAnyNonextensibleElements, bool)
  DECL_GETTER(HasSealedElements, bool)
  DECL_GETTER(HasSharedArrayElements, bool)
  DECL_GETTER(HasNonextensibleElements, bool)

  DECL_GETTER(HasTypedArrayOrRabGsabTypedArrayElements, bool)

  DECL_GETTER(HasFixedUint8ClampedElements, bool)
  DECL_GETTER(HasFixedArrayElements, bool)
  DECL_GETTER(HasFixedInt8Elements, bool)
  DECL_GETTER(HasFixedUint8Elements, bool)
  DECL_GETTER(HasFixedInt16Elements, bool)
  DECL_GETTER(HasFixedUint16Elements, bool)
  DECL_GETTER(HasFixedInt32Elements, bool)
  DECL_GETTER(HasFixedUint32Elements, bool)
  DECL_GETTER(HasFixedFloat16Elements, bool)
  DECL_GETTER(HasFixedFloat32Elements, bool)
  DECL_GETTER(HasFixedFloat64Elements, bool)
  DECL_GETTER(HasFixedBigInt64Elements, bool)
  DECL_GETTER(HasFixedBigUint64Elements, bool)

  DECL_GETTER(HasFastArgumentsElements, bool)
  DECL_GETTER(HasSlowArgumentsElements, bool)
  DECL_GETTER(HasFastStringWrapperElements, bool)
  DECL_GETTER(HasSlowStringWrapperElements, bool)
  bool HasEnumerableElements();

  // Gets slow elements.
  DECL_GETTER(element_dictionary, Tagged<NumberDictionary>)

  // Requires: HasFastElements().
  static void EnsureWritableFastElements(DirectHandle<JSObject> object);

  V8_WARN_UNUSED_RESULT static Maybe<InterceptorResult>
  SetPropertyWithInterceptor(LookupIterator* it,
                             Maybe<ShouldThrow> should_throw,
                             Handle<Object> value);

  // The API currently still wants DefineOwnPropertyIgnoreAttributes to convert
  // AccessorInfo objects to data fields. We allow FORCE_FIELD as an exception
  // to the default behavior that calls the setter.
  enum AccessorInfoHandling { FORCE_FIELD, DONT_FORCE_FIELD };

  V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  DefineOwnPropertyIgnoreAttributes(
      LookupIterator* it, Handle<Object> value, PropertyAttributes attributes,
      AccessorInfoHandling handling = DONT_FORCE_FIELD,
      EnforceDefineSemantics semantics = EnforceDefineSemantics::kSet);

  V8_WARN_UNUSED_RESULT static Maybe<bool> DefineOwnPropertyIgnoreAttributes(
      LookupIterator* it, Handle<Object> value, PropertyAttributes attributes,
      Maybe<ShouldThrow> should_throw,
      AccessorInfoHandling handling = DONT_FORCE_FIELD,
      EnforceDefineSemantics semantics = EnforceDefineSemantics::kSet,
      StoreOrigin store_origin = StoreOrigin::kNamed);

  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> V8_EXPORT_PRIVATE
  SetOwnPropertyIgnoreAttributes(Handle<JSObject> object, Handle<Name> name,
                                 Handle<Object> value,
                                 PropertyAttributes attributes);

  V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  SetOwnElementIgnoreAttributes(Handle<JSObject> object, size_t index,
                                Handle<Object> value,
                                PropertyAttributes attributes);

  // Equivalent to one of the above depending on whether |name| can be converted
  // to an array index.
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  DefinePropertyOrElementIgnoreAttributes(Handle<JSObject> object,
                                          Handle<Name> name,
                                          Handle<Object> value,
                                          PropertyAttributes attributes = NONE);

  // Adds or reconfigures a property to attributes NONE. It will fail when it
  // cannot.
  V8_WARN_UNUSED_RESULT static Maybe<bool> CreateDataProperty(
      Isolate* isolate, Handle<JSObject> object, PropertyKey key,
      Handle<Object> value, Maybe<ShouldThrow> should_throw = Just(kDontThrow));

  V8_EXPORT_PRIVATE static void AddProperty(Isolate* isolate,
                                            Handle<JSObject> object,
                                            Handle<Name> name,
                                            DirectHandle<Object> value,
                                            PropertyAttributes attributes);

  // {name} must be a UTF-8 encoded, null-terminated string.
  static void AddProperty(Isolate* isolate, Handle<JSObject> object,
                          const char* name, DirectHandle<Object> value,
                          PropertyAttributes attributes);

  V8_EXPORT_PRIVATE static Maybe<bool> AddDataElement(
      Handle<JSObject> receiver, uint32_t index, DirectHandle<Object> value,
      PropertyAttributes attributes);

  // Extend the receiver with a single fast property appeared first in the
  // passed map. This also extends the property backing store if necessary.
  static void AllocateStorageForMap(Handle<JSObject> object, Handle<Map> map);

  // Migrates the given object to a map whose field representations are the
  // lowest upper bound of all known representations for that field.
  static void MigrateInstance(Isolate* isolate,
                              DirectHandle<JSObject> instance);

  // Migrates the given object only if the target map is already available,
  // or returns false if such a map is not yet available.
  static bool TryMigrateInstance(Isolate* isolate,
                                 DirectHandle<JSObject> instance);

  // Sets the property value in a normalized object given (key, value, details).
  // Handles the special representation of JS global objects.
  static void SetNormalizedProperty(Handle<JSObject> object, Handle<Name> name,
                                    Handle<Object> value,
                                    PropertyDetails details);
  static void SetNormalizedElement(Handle<JSObject> object, uint32_t index,
                                   Handle<Object> value,
                                   PropertyDetails details);

  static void OptimizeAsPrototype(DirectHandle<JSObject> object,
                                  bool enable_setup_mode = true);
  static void ReoptimizeIfPrototype(DirectHandle<JSObject> object);
  static void MakePrototypesFast(Handle<Object> receiver,
                                 WhereToStart where_to_start, Isolate* isolate);
  static void LazyRegisterPrototypeUser(DirectHandle<Map> user,
                                        Isolate* isolate);
  static void UpdatePrototypeUserRegistration(DirectHandle<Map> old_map,
                                              DirectHandle<Map> new_map,
                                              Isolate* isolate);
  static bool UnregisterPrototypeUser(DirectHandle<Map> user, Isolate* isolate);
  static Tagged<Map> InvalidatePrototypeChains(Tagged<Map> map);
  static void InvalidatePrototypeValidityCell(Tagged<JSGlobalObject> global);

  // Updates prototype chain tracking information when an object changes its
  // map from |old_map| to |new_map|.
  static void NotifyMapChange(DirectHandle<Map> old_map,
                              DirectHandle<Map> new_map, Isolate* isolate);

  // Utility used by many Array builtins and runtime functions
  static inline bool PrototypeHasNoElements(Isolate* isolate,
                                            Tagged<JSObject> object);

  // To be passed to PrototypeUsers::Compact.
  static void PrototypeRegistryCompactionCallback(Tagged<HeapObject> value,
                                                  int old_index, int new_index);

  // Retrieve interceptors.
  DECL_GETTER(GetNamedInterceptor, Tagged<InterceptorInfo>)
  DECL_GETTER(GetIndexedInterceptor, Tagged<InterceptorInfo>)

  // Used from JSReceiver.
  V8_WARN_UNUSED_RESULT static Maybe<PropertyAttributes>
  GetPropertyAttributesWithInterceptor(LookupIterator* it);
  V8_WARN_UNUSED_RESULT static Maybe<PropertyAttributes>
  GetPropertyAttributesWithFailedAccessCheck(LookupIterator* it);

  // Defines an AccessorPair property on the given object.
  V8_EXPORT_PRIVATE static MaybeHandle<Object>
  DefineOwnAccessorIgnoreAttributes(Handle<JSObject> object, Handle<Name> name,
                                    DirectHandle<Object> getter,
                                    DirectHandle<Object> setter,
                                    PropertyAttributes attributes);
  static MaybeHandle<Object> DefineOwnAccessorIgnoreAttributes(
      LookupIterator* it, DirectHandle<Object> getter,
      DirectHandle<Object> setter, PropertyAttributes attributes);

  // Defines an AccessorInfo property on the given object.
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> SetAccessor(
      Handle<JSObject> object, Handle<Name> name, Handle<AccessorInfo> info,
      PropertyAttributes attributes);

  // Check if a data property can be created on the object. It will fail with
  // an error when it cannot.
  V8_WARN_UNUSED_RESULT static Maybe<bool> CheckIfCanDefineAsConfigurable(
      Isolate* isolate, LookupIterator* it, DirectHandle<Object> value,
      Maybe<ShouldThrow> should_throw);

  // The result must be checked first for exceptions. If there's no exception,
  // the output parameter |done| indicates whether the interceptor has a result
  // or not.
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSAny> GetPropertyWithInterceptor(
      LookupIterator* it, bool* done);

  static void ValidateElements(Tagged<JSObject> object);

  // Makes sure that this object can contain HeapObject as elements.
  static inline void EnsureCanContainHeapObjectElements(Handle<JSObject> obj);

  // Makes sure that this object can contain the specified elements.
  // TSlot here is either ObjectSlot or FullObjectSlot.
  template <typename TSlot>
  static inline void EnsureCanContainElements(Handle<JSObject> object,
                                              TSlot elements, uint32_t count,
                                              EnsureElementsMode mode);
  static inline void EnsureCanContainElements(Handle<JSObject> object,
                                              Handle<FixedArrayBase> elements,
                                              uint32_t length,
                                              EnsureElementsMode mode);
  static void EnsureCanContainElements(Handle<JSObject> object,
                                       JavaScriptArguments* arguments,
                                       uint32_t arg_count,
                                       EnsureElementsMode mode);

  // Would we convert a fast elements array to dictionary mode given
  // an access at key?
  bool WouldConvertToSlowElements(uint32_t index);

  static const uint32_t kMinAddedElementsCapacity = 16;

  // Computes the new capacity when expanding the elements of a JSObject.
  static uint32_t NewElementsCapacity(uint32_t old_capacity) {
    // (old_capacity + 50%) + kMinAddedElementsCapacity
    return old_capacity + (old_capacity >> 1) + kMinAddedElementsCapacity;
  }

  // These methods do not perform access checks!
  template <AllocationSiteUpdateMode update_or_check =
                AllocationSiteUpdateMode::kUpdate>
  static bool UpdateAllocationSite(DirectHandle<JSObject> object,
                                   ElementsKind to_kind);

  // Lookup interceptors are used for handling properties controlled by host
  // objects.
  DECL_GETTER(HasNamedInterceptor, bool)
  DECL_GETTER(HasIndexedInterceptor, bool)

  // Support functions for v8 api (needed for correct interceptor behavior).
  V8_WARN_UNUSED_RESULT static Maybe<bool> HasRealNamedProperty(
      Isolate* isolate, Handle<JSObject> object, Handle<Name> name);
  V8_WARN_UNUSED_RESULT static Maybe<bool> HasRealElementProperty(
      Isolate* isolate, Handle<JSObject> object, uint32_t index);
  V8_WARN_UNUSED_RESULT static Maybe<bool> HasRealNamedCallbackProperty(
      Isolate* isolate, Handle<JSObject> object, Handle<Name> name);

  // Get the header size for a JSObject.  Used to compute the index of
  // embedder fields as well as the number of embedder fields.
  // The |function_has_prototype_slot| parameter is needed only for
  // JSFunction objects.
  static V8_EXPORT_PRIVATE int GetHeaderSize(
      InstanceType instance_type, bool function_has_prototype_slot = false);
  static inline int GetHeaderSize(Tagged<Map> map);

  static inline bool MayHaveEmbedderFields(Tagged<Map> map);
  inline bool MayHaveEmbedderFields() const;

  static inline int GetEmbedderFieldsStartOffset(Tagged<Map> map);
  inline int GetEmbedderFieldsStartOffset();

  static inline int GetEmbedderFieldCount(Tagged<Map> map);
  inline int GetEmbedderFieldCount() const;
  inline int GetEmbedderFieldOffset(int index);
  inline Tagged<Object> GetEmbedderField(int index);
  inline void SetEmbedderField(int index, Tagged<Object> value);
  inline void SetEmbedderField(int index, Tagged<Smi> value);

  // Returns true if this object is an Api object which can, if unmodified, be
  // dropped during minor GC because the embedder can recreate it again later.
  static inline bool IsDroppableApiObject(Tagged<Map>);
  inline bool IsDroppableApiObject() const;

  // Returns a new map with all transitions dropped from the object's current
  // map and the ElementsKind set.
  static Handle<Map> GetElementsTransitionMap(DirectHandle<JSObject> object,
                                              ElementsKind to_kind);
  V8_EXPORT_PRIVATE static void TransitionElementsKind(Handle<JSObject> object,
                                                       ElementsKind to_kind);

  // Always use this to migrate an object to a new map.
  // |expected_additional_properties| is only used for fast-to-slow transitions
  // and ignored otherwise.
  V8_EXPORT_PRIVATE static void MigrateToMap(
      Isolate* isolate, DirectHandle<JSObject> object,
      DirectHandle<Map> new_map, int expected_additional_properties = 0);

  // Forces a prototype without any of the checks that the regular SetPrototype
  // would do.
  static void ForceSetPrototype(Isolate* isolate, DirectHandle<JSObject> object,
                                Handle<JSPrototype> proto);

  // Convert the object to use the canonical dictionary
  // representation. If the object is e
```