Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/api/api.cc`. I need to go through each function definition and explain what it does. I also need to address the specific points raised by the user:

1. **List the functionality:**  This requires summarizing the purpose of each method.
2. **Torque source:** Check if the file ends in `.tq`. It doesn't.
3. **Javascript relationship:** If a function relates to JavaScript functionality, provide a JavaScript example.
4. **Code logic reasoning:** If a function has conditional logic, give an example of input and output.
5. **Common programming errors:** If a function's usage might lead to common errors, illustrate with an example.
6. **Overall function:** Provide a concise summary of the snippet's role within V8.
7. **Part number:** Acknowledge that this is part 7 of 15.

Let's go through each function:

* **`GetConstructorName()`:** Retrieves the constructor name of an object.
* **`SetIntegrityLevel()`:** Sets the integrity level (sealed or frozen) of an object.
* **`Delete()` (with `Local<Value> key`):** Deletes a property from an object. Handles JSProxies differently.
* **`DeletePrivate()`:** Deletes a private property from an object.
* **`Has()` (with `Local<Value> key`):** Checks if an object has a given property. Handles array indices separately.
* **`HasPrivate()`:** Checks if an object has a given private property.
* **`Delete()` (with `uint32_t index`):** Deletes an element from an array.
* **`Has()` (with `uint32_t index`):** Checks if an array has an element at a given index.
* **`ObjectSetAccessor()`:** A template function to set up an accessor (getter/setter) on an object.
* **`SetAccessorProperty()`:** Sets an accessor property using `Function` objects for getter and setter.
* **`SetNativeDataProperty()`:** Sets a native C++ function as an accessor.
* **`SetLazyDataProperty()`:** Sets a native C++ function as a lazy accessor.
* **`HasOwnProperty()` (with `Local<Name> key`):** Checks if an object has its *own* property.
* **`HasOwnProperty()` (with `uint32_t index`):** Checks if an object has its *own* element.
* **`HasRealNamedProperty()`:** Checks if an object has a named property that is not an accessor or in the prototype chain.
* **`HasRealIndexedProperty()`:** Checks if an object has an indexed property that is not an accessor or in the prototype chain.
* **`HasRealNamedCallbackProperty()`:** Checks if an object has a named property backed by a callback.
* **`HasNamedLookupInterceptor()`:** Checks for a named lookup interceptor.
* **`HasIndexedLookupInterceptor()`:** Checks for an indexed lookup interceptor.
* **`GetRealNamedPropertyInPrototypeChain()`:** Gets a real named property from the prototype chain.
* **`GetRealNamedPropertyAttributesInPrototypeChain()`:** Gets attributes of a real named property in the prototype chain.
* **`GetRealNamedProperty()`:** Gets a real named property directly on the object.
* **`GetRealNamedPropertyAttributes()`:** Gets attributes of a real named property directly on the object.
* **`Clone()` (with `Isolate*`):** Creates a shallow clone of a JSObject.
* **`Clone()`:** Overload using the current isolate.
* **`GetCreationContextImpl()`:** (Internal) Gets the creation context of an object.
* **`GetCreationContext()` (with `v8::Isolate*`):** Gets the creation context.
* **`GetCreationContext()`:** Overload using the current isolate.
* **`GetCreationContext()` (with `PersistentBase<Object>&`):** Gets the creation context from a persistent object.
* **`GetCreationContextCheckedImpl()`:** (Internal) Gets the creation context and asserts it exists.
* **`GetCreationContextChecked()` (with `v8::Isolate*`):** Gets the creation context, throwing an error if not found.
* **`GetCreationContextChecked()`:** Overload using the current isolate.
* **`GetAlignedPointerFromEmbedderDataInCreationContextImpl()`:** (Internal) Gets aligned embedder data from the creation context.
* **`GetAlignedPointerFromEmbedderDataInCreationContext()` (with `v8::Isolate*`):** Gets aligned embedder data.
* **`GetAlignedPointerFromEmbedderDataInCreationContext()`:** Overload using the current isolate.
* **`GetIdentityHash()`:** Gets the identity hash of an object.
* **`IsCallable()`:** Checks if an object is callable.
* **`IsConstructor()`:** Checks if an object is a constructor.
* **`IsApiWrapper()`:** Checks if an object is an API wrapper.
* **`IsUndetectable()`:** Checks if an object is undetectable.
* **`PrepareArguments()`:** (Internal) Prepares arguments for function calls.
* **`CallAsFunction()`:** Calls an object as a function.
* **`CallAsConstructor()`:** Calls an object as a constructor.
* **`Function::New()`:** Creates a new function object.
* **`Function::NewInstance()`:** Creates a new instance of a function (constructor).
* **`Function::NewInstanceWithSideEffectType()`:**  Similar to `NewInstance` but allows specifying side effect type.
* **`Function::Call()` (with `v8::Isolate*`):** Calls a function.
* **`Function::Call()`:** Overload using the current isolate.
* **`Function::SetName()`:** Sets the name of a function.
* **`Function::GetName()`:** Gets the name of a function.
* **`Function::GetInferredName()`:** Gets the inferred name of a function.
* **`Function::GetDebugName()`:** Gets the debug name of a function.
* **`Function::GetScriptOrigin()`:** Gets the script origin of a function.
* **`Function::GetScriptLineNumber()`:** Gets the script line number of a function's definition.
* **`Function::GetScriptColumnNumber()`:** Gets the script column number of a function's definition.
* **`Function::GetScriptStartPosition()`:** Gets the starting position in the script.
* **`Function::ScriptId()`:** Gets the script ID.
* **`Function::GetBoundFunction()`:** Gets the target function of a bound function.
* **`Function::Experimental_IsNopFunction()`:** Checks if a function is a no-op.

Now, let's organize the information for the final response.
这是目录为`v8/src/api/api.cc`的 V8 源代码片段，它主要负责实现 **V8 JavaScript 引擎的 C++ API 中与对象 (Object) 和函数 (Function) 操作相关的接口**。 这些接口允许 C++ 代码与 JavaScript 对象和函数进行交互，例如创建、删除属性、调用函数等。

**功能列举:**

1. **获取构造函数名:**  `GetConstructorName()`  获取一个 JavaScript 对象的构造函数的名字。
2. **设置完整性级别:** `SetIntegrityLevel()`  设置一个 JavaScript 对象的完整性级别（例如，密封或冻结）。
3. **删除属性:** `Delete()`  从一个 JavaScript 对象中删除指定的属性（通过键名或索引）。
4. **删除私有属性:** `DeletePrivate()` 从一个 JavaScript 对象中删除指定的私有属性。
5. **检查属性是否存在:** `Has()`  检查一个 JavaScript 对象是否拥有指定的属性（通过键名或索引）。
6. **检查私有属性是否存在:** `HasPrivate()` 检查一个 JavaScript 对象是否拥有指定的私有属性。
7. **设置访问器属性:** `SetAccessorProperty()`  为一个 JavaScript 对象设置访问器属性 (getter 和 setter)。
8. **设置原生数据属性:** `SetNativeDataProperty()`  为一个 JavaScript 对象设置由原生 C++ 函数实现的访问器属性。
9. **设置惰性数据属性:** `SetLazyDataProperty()` 为一个 JavaScript 对象设置惰性加载的访问器属性。
10. **检查自身属性:** `HasOwnProperty()` 检查一个 JavaScript 对象是否直接拥有指定的属性（不包括原型链上的属性）。
11. **检查真实命名属性/索引属性:** `HasRealNamedProperty()`, `HasRealIndexedProperty()` 检查对象是否直接拥有特定的命名或索引属性，排除访问器等。
12. **检查真实命名回调属性:** `HasRealNamedCallbackProperty()` 检查对象是否拥有由回调函数支持的命名属性。
13. **检查查找拦截器:** `HasNamedLookupInterceptor()`, `HasIndexedLookupInterceptor()` 检查对象是否定义了命名或索引属性的查找拦截器。
14. **在原型链上获取属性:** `GetRealNamedPropertyInPrototypeChain()`, `GetRealNamedPropertyAttributesInPrototypeChain()` 在对象的原型链上查找并获取指定的命名属性及其属性。
15. **获取属性:** `GetRealNamedProperty()`, `GetRealNamedPropertyAttributes()` 获取对象自身直接拥有的指定命名属性及其属性。
16. **克隆对象:** `Clone()` 创建一个 JavaScript 对象的浅拷贝。
17. **获取创建上下文:** `GetCreationContext()`, `GetCreationContextChecked()` 获取创建该 JavaScript 对象的上下文。
18. **获取创建上下文中嵌入数据的指针:** `GetAlignedPointerFromEmbedderDataInCreationContext()` 获取与对象创建上下文关联的嵌入数据的指针。
19. **获取标识哈希值:** `GetIdentityHash()` 获取 JavaScript 对象的唯一标识哈希值。
20. **检查可调用/可构造:** `IsCallable()`, `IsConstructor()` 检查 JavaScript 对象是否可以作为函数或构造函数调用。
21. **检查 API 包装器:** `IsApiWrapper()` 检查 JavaScript 对象是否是 C++ API 对象的包装器。
22. **检查不可检测性:** `IsUndetectable()` 检查 JavaScript 对象是否被标记为不可检测。
23. **作为函数调用:** `CallAsFunction()`  将一个 JavaScript 对象作为函数调用。
24. **作为构造函数调用:** `CallAsConstructor()` 将一个 JavaScript 对象作为构造函数调用。
25. **创建函数:** `Function::New()` 创建一个新的 JavaScript 函数对象。
26. **创建函数实例:** `Function::NewInstance()`, `Function::NewInstanceWithSideEffectType()` 创建一个 JavaScript 函数（构造函数）的实例。
27. **调用函数:** `Function::Call()` 调用一个 JavaScript 函数。
28. **设置/获取函数名:** `Function::SetName()`, `Function::GetName()`, `Function::GetInferredName()`, `Function::GetDebugName()` 设置和获取 JavaScript 函数的各种名称。
29. **获取函数脚本信息:** `Function::GetScriptOrigin()`, `Function::GetScriptLineNumber()`, `Function::GetScriptColumnNumber()`, `Function::GetScriptStartPosition()`, `Function::ScriptId()` 获取定义 JavaScript 函数的脚本的来源、行号、列号、起始位置和 ID。
30. **获取绑定函数:** `Function::GetBoundFunction()` 获取一个绑定函数的原始目标函数。
31. **实验性检查是否为 NOP 函数:** `Function::Experimental_IsNopFunction()`  检查一个函数是否是无操作函数。

**关于 .tq 文件:**

`v8/src/api/api.cc` 文件是以 `.cc` 结尾的，所以它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码文件。V8 Torque 源代码文件以 `.tq` 结尾。

**与 JavaScript 功能的关系及示例:**

这些 C++ API 接口直接对应了 JavaScript 中对对象和函数的操作。以下是一些 JavaScript 示例说明它们的关系：

1. **`GetConstructorName()`:**

   ```javascript
   const obj = new Date();
   // 在 C++ 中调用 obj->GetConstructorName() 将返回 "Date"
   console.log(obj.constructor.name); // JavaScript 中获取构造函数名
   ```

2. **`SetIntegrityLevel()`:**

   ```javascript
   const obj = { a: 1 };
   Object.seal(obj); // 在 C++ 中调用 obj->SetIntegrityLevel(context, v8::IntegrityLevel::kSealed)
   obj.b = 2; // 严格模式下会报错，非严格模式下静默失败
   console.log(Object.isSealed(obj)); // true
   ```

3. **`Delete()`:**

   ```javascript
   const obj = { a: 1, b: 2 };
   delete obj.a; // 在 C++ 中调用 obj->Delete(context, String::NewFromUtf8Literal(isolate, "a"))
   console.log(obj.a); // undefined
   ```

4. **`Has()`:**

   ```javascript
   const obj = { a: 1 };
   console.log('a' in obj); // true, 在 C++ 中调用 obj->Has(context, String::NewFromUtf8Literal(isolate, "a"))
   console.log('toString' in obj); // true (继承的属性)
   ```

5. **`SetAccessorProperty()`:**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'fullName', {
       get() { return 'John Doe'; },
       set(value) { console.log('Setting fullName to', value); }
   });
   // 上述操作可以通过 C++ 中的 SetAccessorProperty 实现
   console.log(obj.fullName); // John Doe
   obj.fullName = 'Jane Doe'; // Setting fullName to Jane Doe
   ```

6. **`CallAsFunction()`:**

   ```javascript
   const func = function() { console.log('Hello'); };
   func(); // 在 C++ 中可以调用 func_obj->CallAsFunction(context, context->Global(), 0, nullptr)
   ```

7. **`CallAsConstructor()`:**

   ```javascript
   function MyClass(value) { this.value = value; }
   const instance = new MyClass(10); // 在 C++ 中可以调用 constructor_obj->CallAsConstructor(context, 1, &arg)
   console.log(instance.value); // 10
   ```

**代码逻辑推理示例:**

以 `Delete()` 方法为例，它会检查对象是否为 `JSProxy`，并根据情况调用不同的内部函数：

**假设输入:**

* `context`: 一个有效的 V8 上下文对象。
* `obj`: 一个 JavaScript 对象，例如 `{ a: 1, b: 2 }`。
* `key`:  一个 V8 的 `Local<Value>` 对象，代表要删除的属性名，例如字符串 "a"。

**输出:**

* 如果 `obj` 不是 `JSProxy`，`i::Runtime::DeleteObjectProperty` 将被调用，尝试删除 `obj` 的属性 "a"。如果删除成功，方法返回 `Just(true)`，否则返回 `Just(false)`。
* 如果 `obj` 是 `JSProxy`，则会执行额外的脚本逻辑来处理删除操作，结果同样是 `Just(true)` 或 `Just(false)`。

**常见编程错误示例:**

使用 `SetIntegrityLevel()` 时，一个常见的错误是在设置完整性级别后尝试修改对象的属性，这会导致错误（在严格模式下）或静默失败（在非严格模式下）。

```javascript
"use strict";
const obj = { a: 1 };
Object.seal(obj);
obj.b = 2; // TypeError: Cannot add property b, object is sealed
```

在 C++ 中，如果没有正确处理 `Maybe` 类型返回值，也可能导致错误。例如，如果 `Delete()` 操作失败并返回 `Nothing<bool>()`，而 C++ 代码没有检查这种情况，就可能导致未定义的行为。

**功能归纳:**

这个代码片段是 V8 引擎 C++ API 的一部分，专注于提供操作 JavaScript **对象 (Object)** 和 **函数 (Function)** 的底层接口。它允许 C++ 代码执行诸如属性访问、修改、删除，以及函数调用、构造等关键的 JavaScript 操作。这些接口是构建 V8 更高层 API 和与 JavaScript 代码进行互操作的基础。

这是第 **7** 部分，共 **15** 部分，说明这部分代码专注于 V8 API 中与对象和函数操作相关的核心功能。

### 提示词
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
:GetConstructorName() {
  // TODO(v8:12547): Consider adding GetConstructorName(Local<Context>).
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate;
  if (i::HeapLayout::InWritableSharedSpace(*self)) {
    i_isolate = i::Isolate::Current();
  } else {
    i_isolate = self->GetIsolate();
  }
  i::Handle<i::String> name =
      i::JSReceiver::GetConstructorName(i_isolate, self);
  return Utils::ToLocal(name);
}

Maybe<bool> v8::Object::SetIntegrityLevel(Local<Context> context,
                                          IntegrityLevel level) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, SetIntegrityLevel, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  i::JSReceiver::IntegrityLevel i_level =
      level == IntegrityLevel::kFrozen ? i::FROZEN : i::SEALED;
  Maybe<bool> result = i::JSReceiver::SetIntegrityLevel(
      i_isolate, self, i_level, i::kThrowOnError);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::Delete(Local<Context> context, Local<Value> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  if (i::IsJSProxy(*self)) {
    ENTER_V8(i_isolate, context, Object, Delete, i::HandleScope);
    Maybe<bool> result = i::Runtime::DeleteObjectProperty(
        i_isolate, self, key_obj, i::LanguageMode::kSloppy);
    has_exception = result.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return result;
  } else {
    // If it's not a JSProxy, i::Runtime::DeleteObjectProperty should never run
    // a script.
    DCHECK(i::IsJSObject(*self) || i::IsWasmObject(*self));
    ENTER_V8_NO_SCRIPT(i_isolate, context, Object, Delete, i::HandleScope);
    Maybe<bool> result = i::Runtime::DeleteObjectProperty(
        i_isolate, self, key_obj, i::LanguageMode::kSloppy);
    has_exception = result.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return result;
  }
}

Maybe<bool> v8::Object::DeletePrivate(Local<Context> context,
                                      Local<Private> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  // In case of private symbols, i::Runtime::DeleteObjectProperty does not run
  // any author script.
  ENTER_V8_NO_SCRIPT(i_isolate, context, Object, Delete, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  Maybe<bool> result = i::Runtime::DeleteObjectProperty(
      i_isolate, self, key_obj, i::LanguageMode::kSloppy);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::Has(Local<Context> context, Local<Value> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Has, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  Maybe<bool> maybe = Nothing<bool>();
  // Check if the given key is an array index.
  uint32_t index = 0;
  if (i::Object::ToArrayIndex(*key_obj, &index)) {
    maybe = i::JSReceiver::HasElement(i_isolate, self, index);
  } else {
    // Convert the key to a name - possibly by calling back into JavaScript.
    i::Handle<i::Name> name;
    if (i::Object::ToName(i_isolate, key_obj).ToHandle(&name)) {
      maybe = i::JSReceiver::HasProperty(i_isolate, self, name);
    }
  }
  has_exception = maybe.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return maybe;
}

Maybe<bool> v8::Object::HasPrivate(Local<Context> context, Local<Private> key) {
  return HasOwnProperty(context, key.UnsafeAs<Name>());
}

Maybe<bool> v8::Object::Delete(Local<Context> context, uint32_t index) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Delete, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  Maybe<bool> result = i::JSReceiver::DeleteElement(i_isolate, self, index);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::Has(Local<Context> context, uint32_t index) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Has, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto maybe = i::JSReceiver::HasElement(i_isolate, self, index);
  has_exception = maybe.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return maybe;
}

template <typename Getter, typename Setter, typename Data>
static Maybe<bool> ObjectSetAccessor(Local<Context> context, Object* self,
                                     Local<Name> name, Getter getter,
                                     Setter setter, Data data,
                                     PropertyAttribute attributes,
                                     bool replace_on_access,
                                     SideEffectType getter_side_effect_type,
                                     SideEffectType setter_side_effect_type) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, Object, SetAccessor, i::HandleScope);
  if (!IsJSObject(*Utils::OpenDirectHandle(self))) return Just(false);
  auto obj = i::Cast<i::JSObject>(Utils::OpenHandle(self));
  i::Handle<i::AccessorInfo> info = MakeAccessorInfo(
      i_isolate, name, getter, setter, data, replace_on_access);
  info->set_getter_side_effect_type(getter_side_effect_type);
  info->set_setter_side_effect_type(setter_side_effect_type);
  if (info.is_null()) return Nothing<bool>();
  bool fast = obj->HasFastProperties();
  i::Handle<i::Object> result;

  i::Handle<i::Name> accessor_name(info->name(), i_isolate);
  i::PropertyAttributes attrs = static_cast<i::PropertyAttributes>(attributes);
  has_exception = !i::JSObject::SetAccessor(obj, accessor_name, info, attrs)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  if (i::IsUndefined(*result, i_isolate)) return Just(false);
  if (fast) {
    i::JSObject::MigrateSlowToFast(obj, 0, "APISetAccessor");
  }
  return Just(true);
}

void Object::SetAccessorProperty(Local<Name> name, Local<Function> getter,
                                 Local<Function> setter,
                                 PropertyAttribute attributes) {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  if (!IsJSObject(*self)) return;
  i::Handle<i::JSReceiver> getter_i = v8::Utils::OpenHandle(*getter);
  i::Handle<i::JSAny> setter_i = v8::Utils::OpenHandle(*setter, true);
  if (setter_i.is_null()) setter_i = i_isolate->factory()->null_value();

  i::PropertyDescriptor desc;
  desc.set_enumerable(!(attributes & v8::DontEnum));
  desc.set_configurable(!(attributes & v8::DontDelete));
  desc.set_get(getter_i);
  desc.set_set(setter_i);

  auto name_i = v8::Utils::OpenHandle(*name);
  // DefineOwnProperty might still throw if the receiver is a JSProxy and it
  // might fail if the receiver is non-extensible or already has this property
  // as non-configurable.
  Maybe<bool> success = i::JSReceiver::DefineOwnProperty(
      i_isolate, self, name_i, &desc, Just(i::kDontThrow));
  USE(success);
}

Maybe<bool> Object::SetNativeDataProperty(
    v8::Local<v8::Context> context, v8::Local<Name> name,
    AccessorNameGetterCallback getter, AccessorNameSetterCallback setter,
    v8::Local<Value> data, PropertyAttribute attributes,
    SideEffectType getter_side_effect_type,
    SideEffectType setter_side_effect_type) {
  return ObjectSetAccessor(context, this, name, getter, setter, data,
                           attributes, false, getter_side_effect_type,
                           setter_side_effect_type);
}

Maybe<bool> Object::SetLazyDataProperty(
    v8::Local<v8::Context> context, v8::Local<Name> name,
    AccessorNameGetterCallback getter, v8::Local<Value> data,
    PropertyAttribute attributes, SideEffectType getter_side_effect_type,
    SideEffectType setter_side_effect_type) {
  return ObjectSetAccessor(context, this, name, getter,
                           static_cast<AccessorNameSetterCallback>(nullptr),
                           data, attributes, true, getter_side_effect_type,
                           setter_side_effect_type);
}

Maybe<bool> v8::Object::HasOwnProperty(Local<Context> context,
                                       Local<Name> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, HasOwnProperty, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_val = Utils::OpenHandle(*key);
  auto result = i::JSReceiver::HasOwnProperty(i_isolate, self, key_val);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::HasOwnProperty(Local<Context> context, uint32_t index) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, HasOwnProperty, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto result = i::JSReceiver::HasOwnProperty(i_isolate, self, index);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::HasRealNamedProperty(Local<Context> context,
                                             Local<Name> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, Object, HasRealNamedProperty,
                     i::HandleScope);
  auto self = Utils::OpenHandle(this);
  if (!IsJSObject(*self)) return Just(false);
  auto key_val = Utils::OpenHandle(*key);
  auto result = i::JSObject::HasRealNamedProperty(
      i_isolate, i::Cast<i::JSObject>(self), key_val);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::HasRealIndexedProperty(Local<Context> context,
                                               uint32_t index) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, Object, HasRealIndexedProperty,
                     i::HandleScope);
  auto self = Utils::OpenHandle(this);
  if (!IsJSObject(*self)) return Just(false);
  auto result = i::JSObject::HasRealElementProperty(
      i_isolate, i::Cast<i::JSObject>(self), index);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::HasRealNamedCallbackProperty(Local<Context> context,
                                                     Local<Name> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, Object, HasRealNamedCallbackProperty,
                     i::HandleScope);
  auto self = Utils::OpenHandle(this);
  if (!IsJSObject(*self)) return Just(false);
  auto key_val = Utils::OpenHandle(*key);
  auto result = i::JSObject::HasRealNamedCallbackProperty(
      i_isolate, i::Cast<i::JSObject>(self), key_val);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

bool v8::Object::HasNamedLookupInterceptor() const {
  auto self = *Utils::OpenDirectHandle(this);
  if (!IsJSObject(*self)) return false;
  return i::Cast<i::JSObject>(self)->HasNamedInterceptor();
}

bool v8::Object::HasIndexedLookupInterceptor() const {
  auto self = *Utils::OpenDirectHandle(this);
  if (!IsJSObject(*self)) return false;
  return i::Cast<i::JSObject>(self)->HasIndexedInterceptor();
}

MaybeLocal<Value> v8::Object::GetRealNamedPropertyInPrototypeChain(
    Local<Context> context, Local<Name> key) {
  PREPARE_FOR_EXECUTION(context, Object, GetRealNamedPropertyInPrototypeChain);
  auto self = Utils::OpenHandle(this);
  if (!IsJSObject(*self)) return MaybeLocal<Value>();
  auto key_obj = Utils::OpenHandle(*key);
  i::PrototypeIterator iter(i_isolate, self);
  if (iter.IsAtEnd()) return MaybeLocal<Value>();
  i::Handle<i::JSReceiver> proto =
      i::PrototypeIterator::GetCurrent<i::JSReceiver>(iter);
  i::PropertyKey lookup_key(i_isolate, key_obj);
  i::LookupIterator it(i_isolate, self, lookup_key, proto,
                       i::LookupIterator::PROTOTYPE_CHAIN_SKIP_INTERCEPTOR);
  Local<Value> result;
  has_exception = !ToLocal<Value>(i::Object::GetProperty(&it), &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  if (!it.IsFound()) return MaybeLocal<Value>();
  RETURN_ESCAPED(result);
}

Maybe<PropertyAttribute>
v8::Object::GetRealNamedPropertyAttributesInPrototypeChain(
    Local<Context> context, Local<Name> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object,
           GetRealNamedPropertyAttributesInPrototypeChain, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  if (!IsJSObject(*self)) return Nothing<PropertyAttribute>();
  auto key_obj = Utils::OpenHandle(*key);
  i::PrototypeIterator iter(i_isolate, self);
  if (iter.IsAtEnd()) return Nothing<PropertyAttribute>();
  i::Handle<i::JSReceiver> proto =
      i::PrototypeIterator::GetCurrent<i::JSReceiver>(iter);
  i::PropertyKey lookup_key(i_isolate, key_obj);
  i::LookupIterator it(i_isolate, self, lookup_key, proto,
                       i::LookupIterator::PROTOTYPE_CHAIN_SKIP_INTERCEPTOR);
  Maybe<i::PropertyAttributes> result =
      i::JSReceiver::GetPropertyAttributes(&it);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(PropertyAttribute);
  if (!it.IsFound()) return Nothing<PropertyAttribute>();
  if (result.FromJust() == i::ABSENT) return Just(None);
  return Just(static_cast<PropertyAttribute>(result.FromJust()));
}

MaybeLocal<Value> v8::Object::GetRealNamedProperty(Local<Context> context,
                                                   Local<Name> key) {
  PREPARE_FOR_EXECUTION(context, Object, GetRealNamedProperty);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  i::PropertyKey lookup_key(i_isolate, key_obj);
  i::LookupIterator it(i_isolate, self, lookup_key, self,
                       i::LookupIterator::PROTOTYPE_CHAIN_SKIP_INTERCEPTOR);
  Local<Value> result;
  has_exception = !ToLocal<Value>(i::Object::GetProperty(&it), &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  if (!it.IsFound()) return MaybeLocal<Value>();
  RETURN_ESCAPED(result);
}

Maybe<PropertyAttribute> v8::Object::GetRealNamedPropertyAttributes(
    Local<Context> context, Local<Name> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, GetRealNamedPropertyAttributes,
           i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  i::PropertyKey lookup_key(i_isolate, key_obj);
  i::LookupIterator it(i_isolate, self, lookup_key, self,
                       i::LookupIterator::PROTOTYPE_CHAIN_SKIP_INTERCEPTOR);
  auto result = i::JSReceiver::GetPropertyAttributes(&it);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(PropertyAttribute);
  if (!it.IsFound()) return Nothing<PropertyAttribute>();
  if (result.FromJust() == i::ABSENT) {
    return Just(static_cast<PropertyAttribute>(i::NONE));
  }
  return Just<PropertyAttribute>(
      static_cast<PropertyAttribute>(result.FromJust()));
}

Local<v8::Object> v8::Object::Clone(Isolate* isolate) {
  auto self = i::Cast<i::JSObject>(Utils::OpenHandle(this));
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::JSObject> result = i_isolate->factory()->CopyJSObject(self);
  return Utils::ToLocal(result);
}

Local<v8::Object> v8::Object::Clone() {
  auto self = i::Cast<i::JSObject>(Utils::OpenHandle(this));
  return Clone(reinterpret_cast<v8::Isolate*>(self->GetIsolate()));
}

namespace {
V8_INLINE MaybeLocal<v8::Context> GetCreationContextImpl(
    i::DirectHandle<i::JSReceiver> object, i::Isolate* i_isolate) {
  i::Handle<i::NativeContext> context;
  if (object->GetCreationContext(i_isolate).ToHandle(&context)) {
    return Utils::ToLocal(context);
  }
  return MaybeLocal<v8::Context>();
}
}  // namespace

MaybeLocal<v8::Context> v8::Object::GetCreationContext(v8::Isolate* isolate) {
  auto self = Utils::OpenDirectHandle(this);
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  return GetCreationContextImpl(self, i_isolate);
}

MaybeLocal<v8::Context> v8::Object::GetCreationContext() {
  auto self = Utils::OpenDirectHandle(this);
  return GetCreationContextImpl(self, i::Isolate::Current());
}

MaybeLocal<v8::Context> v8::Object::GetCreationContext(
    const PersistentBase<Object>& object) {
  return object.template value<Object>()->GetCreationContext(
      Isolate::GetCurrent());
}

namespace {
V8_INLINE Local<v8::Context> GetCreationContextCheckedImpl(
    i::DirectHandle<i::JSReceiver> object, i::Isolate* i_isolate) {
  i::Handle<i::NativeContext> context;
  Utils::ApiCheck(object->GetCreationContext(i_isolate).ToHandle(&context),
                  "v8::Object::GetCreationContextChecked",
                  "No creation context available");
  return Utils::ToLocal(context);
}
}  // namespace

Local<v8::Context> v8::Object::GetCreationContextChecked(v8::Isolate* isolate) {
  auto self = Utils::OpenDirectHandle(this);
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  return GetCreationContextCheckedImpl(self, i_isolate);
}

Local<v8::Context> v8::Object::GetCreationContextChecked() {
  auto self = Utils::OpenDirectHandle(this);
  return GetCreationContextCheckedImpl(self, i::Isolate::Current());
}

namespace {
V8_INLINE void* GetAlignedPointerFromEmbedderDataInCreationContextImpl(
    i::DirectHandle<i::JSReceiver> object,
    i::IsolateForSandbox i_isolate_for_sandbox, int index) {
  const char* location =
      "v8::Object::GetAlignedPointerFromEmbedderDataInCreationContext()";
  auto maybe_context = object->GetCreationContext();
  if (!maybe_context.has_value()) return nullptr;

  // The code below mostly mimics Context::GetAlignedPointerFromEmbedderData()
  // but it doesn't try to expand the EmbedderDataArray instance.
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::NativeContext> native_context = maybe_context.value();

  // This macro requires a real Isolate while |i_isolate_for_sandbox| might be
  // nullptr if the V8 sandbox is not enabled.
  DCHECK_NO_SCRIPT_NO_EXCEPTION(native_context->GetIsolate());

  // TODO(ishell): remove cast once embedder_data slot has a proper type.
  i::Tagged<i::EmbedderDataArray> data =
      i::Cast<i::EmbedderDataArray>(native_context->embedder_data());
  if (V8_LIKELY(static_cast<unsigned>(index) <
                static_cast<unsigned>(data->length()))) {
    void* result;
    Utils::ApiCheck(i::EmbedderDataSlot(data, index)
                        .ToAlignedPointer(i_isolate_for_sandbox, &result),
                    location, "Pointer is not aligned");
    return result;
  }
  // Bad index, report an API error.
  Utils::ApiCheck(index >= 0, location, "Negative index");
  Utils::ApiCheck(index < i::EmbedderDataArray::kMaxLength, location,
                  "Index too large");
  return nullptr;
}
}  // namespace

void* v8::Object::GetAlignedPointerFromEmbedderDataInCreationContext(
    v8::Isolate* isolate, int index) {
  auto self = Utils::OpenDirectHandle(this);
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  return GetAlignedPointerFromEmbedderDataInCreationContextImpl(self, i_isolate,
                                                                index);
}

void* v8::Object::GetAlignedPointerFromEmbedderDataInCreationContext(
    int index) {
  auto self = Utils::OpenDirectHandle(this);
  i::IsolateForSandbox isolate = GetIsolateForSandbox(*self);
  return GetAlignedPointerFromEmbedderDataInCreationContextImpl(self, isolate,
                                                                index);
}

int v8::Object::GetIdentityHash() {
  i::DisallowGarbageCollection no_gc;
  auto self = Utils::OpenDirectHandle(this);
  auto i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return self->GetOrCreateIdentityHash(i_isolate).value();
}

bool v8::Object::IsCallable() const {
  return i::IsCallable(*Utils::OpenDirectHandle(this));
}

bool v8::Object::IsConstructor() const {
  return i::IsConstructor(*Utils::OpenDirectHandle(this));
}

bool v8::Object::IsApiWrapper() const {
  auto self = Utils::OpenDirectHandle(this);
  // This checks whether an object of a given instance type can serve as API
  // object. It does not check whether the JS object is wrapped via embedder
  // fields or Wrap()/Unwrap() API.
  return IsJSApiWrapperObject(*self);
}

bool v8::Object::IsUndetectable() const {
  auto self = Utils::OpenDirectHandle(this);
  return i::IsUndetectable(*self);
}

namespace {
#ifdef V8_ENABLE_DIRECT_HANDLE
// A newly allocated vector is required to convert from an array of direct
// locals to an array of indirect handles.
std::vector<i::Handle<i::Object>> PrepareArguments(int argc,
                                                   Local<Value> argv[]) {
  std::vector<i::Handle<i::Object>> args(argc);
  for (int i = 0; i < argc; ++i) {
    args[i] = Utils::OpenHandle(*argv[i]);
  }
  return args;
}
#else   // !V8_ENABLE_DIRECT_HANDLE
// A simple cast is used to convert from an array of indirect locals to an
// array of indirect handles. A MemorySpan object is returned, as no
// deallocation is necessary.
v8::MemorySpan<i::Handle<i::Object>> PrepareArguments(int argc,
                                                      Local<Value> argv[]) {
  return {reinterpret_cast<i::Handle<i::Object>*>(argv),
          static_cast<size_t>(argc)};
}
#endif  // V8_ENABLE_DIRECT_HANDLE
}  // namespace

MaybeLocal<Value> Object::CallAsFunction(Local<Context> context,
                                         Local<Value> recv, int argc,
                                         Local<Value> argv[]) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.Execute");
  ENTER_V8(i_isolate, context, Object, CallAsFunction, InternalEscapableScope);
  i::TimerEventScope<i::TimerEventExecute> timer_scope(i_isolate);
  i::NestedTimedHistogramScope execute_timer(i_isolate->counters()->execute(),
                                             i_isolate);
  auto self = Utils::OpenHandle(this);
  auto recv_obj = Utils::OpenHandle(*recv);
  static_assert(sizeof(v8::Local<v8::Value>) == sizeof(i::Handle<i::Object>));
  auto args = PrepareArguments(argc, argv);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::Call(i_isolate, self, recv_obj, argc, args.data()),
      &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<Value> Object::CallAsConstructor(Local<Context> context, int argc,
                                            Local<Value> argv[]) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.Execute");
  ENTER_V8(i_isolate, context, Object, CallAsConstructor,
           InternalEscapableScope);
  i::TimerEventScope<i::TimerEventExecute> timer_scope(i_isolate);
  i::NestedTimedHistogramScope execute_timer(i_isolate->counters()->execute(),
                                             i_isolate);
  auto self = Utils::OpenHandle(this);
  static_assert(sizeof(v8::Local<v8::Value>) == sizeof(i::Handle<i::Object>));
  auto args = PrepareArguments(argc, argv);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::New(i_isolate, self, self, argc, args.data()), &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<Function> Function::New(Local<Context> context,
                                   FunctionCallback callback, Local<Value> data,
                                   int length, ConstructorBehavior behavior,
                                   SideEffectType side_effect_type) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(*context)->GetIsolate();
  API_RCS_SCOPE(i_isolate, Function, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto templ =
      FunctionTemplateNew(i_isolate, callback, data, Local<Signature>(), length,
                          behavior, true, Local<Private>(), side_effect_type);
  return Utils::ToLocal(templ)->GetFunction(context);
}

MaybeLocal<Object> Function::NewInstance(Local<Context> context, int argc,
                                         v8::Local<v8::Value> argv[]) const {
  return NewInstanceWithSideEffectType(context, argc, argv,
                                       SideEffectType::kHasSideEffect);
}

MaybeLocal<Object> Function::NewInstanceWithSideEffectType(
    Local<Context> context, int argc, v8::Local<v8::Value> argv[],
    SideEffectType side_effect_type) const {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.Execute");
  ENTER_V8(i_isolate, context, Function, NewInstance, InternalEscapableScope);
  i::TimerEventScope<i::TimerEventExecute> timer_scope(i_isolate);
  i::NestedTimedHistogramScope execute_timer(i_isolate->counters()->execute(),
                                             i_isolate);
  auto self = Utils::OpenHandle(this);
  static_assert(sizeof(v8::Local<v8::Value>) == sizeof(i::Handle<i::Object>));
  bool should_set_has_no_side_effect =
      side_effect_type == SideEffectType::kHasNoSideEffect &&
      i_isolate->should_check_side_effects();
  if (should_set_has_no_side_effect) {
    CHECK(IsJSFunction(*self) &&
          i::Cast<i::JSFunction>(*self)->shared()->IsApiFunction());
    i::Tagged<i::FunctionTemplateInfo> func_data =
        i::Cast<i::JSFunction>(*self)->shared()->api_func_data();
    if (func_data->has_callback(i_isolate)) {
      if (func_data->has_side_effects()) {
        i_isolate->debug()->IgnoreSideEffectsOnNextCallTo(
            handle(func_data, i_isolate));
      }
    }
  }
  auto args = PrepareArguments(argc, argv);
  Local<Object> result;
  has_exception = !ToLocal<Object>(
      i::Execution::New(i_isolate, self, self, argc, args.data()), &result);
  RETURN_ON_FAILED_EXECUTION(Object);
  RETURN_ESCAPED(result);
}

MaybeLocal<v8::Value> Function::Call(v8::Isolate* isolate,
                                     Local<Context> context,
                                     v8::Local<v8::Value> recv, int argc,
                                     v8::Local<v8::Value> argv[]) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.Execute");
  ENTER_V8(i_isolate, context, Function, Call, InternalEscapableScope);
  i::TimerEventScope<i::TimerEventExecute> timer_scope(i_isolate);
  i::NestedTimedHistogramScope execute_timer(i_isolate->counters()->execute(),
                                             i_isolate);
  auto self = Utils::OpenHandle(this);
  Utils::ApiCheck(!self.is_null(), "v8::Function::Call",
                  "Function to be called is a null pointer");
  auto recv_obj = Utils::OpenHandle(*recv);
  static_assert(sizeof(v8::Local<v8::Value>) == sizeof(i::Handle<i::Object>));
  auto args = PrepareArguments(argc, argv);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::Call(i_isolate, self, recv_obj, argc, args.data()),
      &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<v8::Value> Function::Call(Local<Context> context,
                                     v8::Local<v8::Value> recv, int argc,
                                     v8::Local<v8::Value> argv[]) {
  return Call(context->GetIsolate(), context, recv, argc, argv);
}

void Function::SetName(v8::Local<v8::String> name) {
  auto self = Utils::OpenDirectHandle(this);
  if (!IsJSFunction(*self)) return;
  auto func = i::Cast<i::JSFunction>(self);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(func->GetIsolate());
  func->shared()->SetName(*Utils::OpenDirectHandle(*name));
}

Local<Value> Function::GetName() const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  if (i::IsJSBoundFunction(*self)) {
    auto func = i::Cast<i::JSBoundFunction>(self);
    i::Handle<i::Object> name;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        i_isolate, name, i::JSBoundFunction::GetName(i_isolate, func),
        Local<Value>());
    return Utils::ToLocal(name);
  }
  if (i::IsJSFunction(*self)) {
    auto func = i::Cast<i::JSFunction>(self);
    return Utils::ToLocal(i::direct_handle(func->shared()->Name(), i_isolate));
  }
  return ToApiHandle<Primitive>(i_isolate->factory()->undefined_value());
}

Local<Value> Function::GetInferredName() const {
  auto self = Utils::OpenDirectHandle(this);
  if (!IsJSFunction(*self)) {
    return ToApiHandle<Primitive>(
        self->GetIsolate()->factory()->undefined_value());
  }
  auto func = i::Cast<i::JSFunction>(self);
  i::Isolate* isolate = func->GetIsolate();
  return Utils::ToLocal(
      i::direct_handle(func->shared()->inferred_name(), isolate));
}

Local<Value> Function::GetDebugName() const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  if (!IsJSFunction(*self)) {
    return ToApiHandle<Primitive>(i_isolate->factory()->undefined_value());
  }
  auto func = i::Cast<i::JSFunction>(self);
  i::DirectHandle<i::String> name = i::JSFunction::GetDebugName(func);
  return Utils::ToLocal(i::direct_handle(*name, i_isolate));
}

ScriptOrigin Function::GetScriptOrigin() const {
  auto self = Utils::OpenDirectHandle(this);
  if (!IsJSFunction(*self)) return v8::ScriptOrigin(Local<Value>());
  auto func = i::Cast<i::JSFunction>(self);
  if (i::IsScript(func->shared()->script())) {
    i::DirectHandle<i::Script> script(
        i::Cast<i::Script>(func->shared()->script()), func->GetIsolate());
    return GetScriptOriginForScript(func->GetIsolate(), script);
  }
  return v8::ScriptOrigin(Local<Value>());
}

const int Function::kLineOffsetNotFound = -1;

int Function::GetScriptLineNumber() const {
  auto self = *Utils::OpenDirectHandle(this);
  if (!IsJSFunction(self)) {
    return kLineOffsetNotFound;
  }
  auto func = i::Cast<i::JSFunction>(self);
  if (i::IsScript(func->shared()->script())) {
    i::DirectHandle<i::Script> script(
        i::Cast<i::Script>(func->shared()->script()), func->GetIsolate());
    return i::Script::GetLineNumber(script, func->shared()->StartPosition());
  }
  return kLineOffsetNotFound;
}

int Function::GetScriptColumnNumber() const {
  auto self = *Utils::OpenDirectHandle(this);
  if (!IsJSFunction(self)) {
    return kLineOffsetNotFound;
  }
  auto func = i::Cast<i::JSFunction>(self);
  if (i::IsScript(func->shared()->script())) {
    i::DirectHandle<i::Script> script(
        i::Cast<i::Script>(func->shared()->script()), func->GetIsolate());
    return i::Script::GetColumnNumber(script, func->shared()->StartPosition());
  }
  return kLineOffsetNotFound;
}

int Function::GetScriptStartPosition() const {
  auto self = *Utils::OpenDirectHandle(this);
  if (!IsJSFunction(self)) {
    return kLineOffsetNotFound;
  }
  auto func = i::Cast<i::JSFunction>(self);
  if (i::IsScript(func->shared()->script())) {
    return func->shared()->StartPosition();
  }
  return kLineOffsetNotFound;
}

int Function::ScriptId() const {
  auto self = *Utils::OpenDirectHandle(this);
  if (!IsJSFunction(self)) return v8::UnboundScript::kNoScriptId;
  auto func = i::Cast<i::JSFunction>(self);
  if (!IsScript(func->shared()->script()))
    return v8::UnboundScript::kNoScriptId;
  return i::Cast<i::Script>(func->shared()->script())->id();
}

Local<v8::Value> Function::GetBoundFunction() const {
  auto self = Utils::OpenDirectHandle(this);
  if (i::IsJSBoundFunction(*self)) {
    auto bound_function = i::Cast<i::JSBoundFunction>(self);
    auto bound_target_function = i::handle(
        bound_function->bound_target_function(), bound_function->GetIsolate());
    return Utils::CallableToLocal(bound_target_function);
  }
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(self->GetIsolate()));
}

bool Function::Experimental_IsNopFunction() const {
  auto self = Utils::OpenDirectHandle(this);
  if (!IsJSFunction(*self)) return false;
  auto sfi = i::Cast<i::JSFunction>(*self)->shared();
  i::Isolate* i_isolate = self->GetIsolate();
  i::IsCompiledScope is_compiled_scope(sfi->is_compiled_scope(i_isolate));
```