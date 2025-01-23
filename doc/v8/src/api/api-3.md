Response: The user wants a summary of the C++ code in `v8/src/api/api.cc`.
This is part 4 of 8, suggesting a larger file with related functionalities.

The code snippet primarily deals with methods of the `v8::Object` and `v8::Function` classes in the V8 API. It also touches upon `v8::String`, `v8::Symbol`, `v8::Private`, and `v8::Number` etc.

The core functionalities revolve around:

- **Object Properties:** Getting constructor names, setting integrity levels, deleting properties (including private ones), checking for property existence (including private, own, real named/indexed properties).
- **Object Accessors:** Setting native and lazy data properties with getters and setters.
- **Object Introspection:** Checking for lookup interceptors, getting real named property in the prototype chain, getting real named property attributes.
- **Object Manipulation:** Cloning objects, getting and checking creation contexts.
- **Object Internals:** Getting and setting internal fields and aligned pointers within them.
- **Function Calls & Construction:** Calling objects as functions or constructors, creating new function instances.
- **Function Properties:** Getting and setting names, inferred names, debug names, script origin information (line number, column number, script ID).
- **String Operations:** Getting length, checking if it's one-byte, getting UTF-8 length, writing to UTF-8 and UTF-16 buffers, checking if it's an external string, internalizing strings.
- **Symbol & Private Operations:** Getting description/name.
- **Primitive Value Access:** Getting the value of Number, Boolean, Integer, Int32, Uint32.
- **Wrapping/Unwrapping:** Functionality related to wrapping C++ objects within V8 objects.
- **V8 Environment Initialization:** Initializing the V8 platform and checking for build configuration mismatches.

Regarding the relationship with JavaScript:  Most of these C++ functions in `api.cc` directly map to JavaScript functionalities.

Let's illustrate with JavaScript examples for some of the key functions.
这是 `v8/src/api/api.cc` 文件的一部分，主要负责实现 **V8 API 中关于对象（`v8::Object`）和函数（`v8::Function`）的常用操作**。它提供了 C++ 接口，使得嵌入 V8 的应用程序能够与 JavaScript 对象和函数进行交互。

**核心功能归纳:**

* **对象属性操作:**
    * 获取构造函数名称 (`GetConstructorName`)
    * 设置对象完整性级别 (冻结/密封) (`SetIntegrityLevel`)
    * 删除对象属性 (包括常规属性和私有属性) (`Delete`)
    * 检查对象是否拥有指定属性 (包括常规属性、私有属性和索引属性) (`Has`, `HasPrivate`, `HasOwnProperty`, `HasRealNamedProperty`, `HasRealIndexedProperty`, `HasRealNamedCallbackProperty`)
* **对象属性定义:**
    * 设置原生数据属性，可以指定 getter 和 setter 回调 (`SetNativeDataProperty`)
    * 设置延迟数据属性，只有在访问时才会调用 getter (`SetLazyDataProperty`)
    * 设置访问器属性，使用 JavaScript 函数作为 getter 和 setter (`SetAccessorProperty`)
* **对象内省:**
    * 检查是否存在命名查找拦截器或索引查找拦截器 (`HasNamedLookupInterceptor`, `HasIndexedLookupInterceptor`)
    * 在原型链上查找并获取指定的命名属性 (`GetRealNamedPropertyInPrototypeChain`)
    * 在原型链上查找并获取指定命名属性的特性 (`GetRealNamedPropertyAttributesInPrototypeChain`)
    * 获取对象自身的指定命名属性 (`GetRealNamedProperty`)
    * 获取对象自身指定命名属性的特性 (`GetRealNamedPropertyAttributes`)
* **对象操作:**
    * 克隆对象 (`Clone`)
    * 获取对象的创建上下文 (`GetCreationContext`, `GetCreationContextChecked`)
    * 获取创建上下文中嵌入数据的对齐指针 (`GetAlignedPointerFromEmbedderDataInCreationContext`)
    * 获取对象的唯一标识哈希值 (`GetIdentityHash`)
    * 判断对象是否可调用 (`IsCallable`)
    * 判断对象是否可作为构造函数 (`IsConstructor`)
    * 判断对象是否是 API 包装器 (`IsApiWrapper`)
    * 判断对象是否不可检测 (`IsUndetectable`)
* **函数操作:**
    * 作为函数调用对象 (`CallAsFunction`)
    * 作为构造函数调用对象 (`CallAsConstructor`)
    * 创建新的函数对象 (`Function::New`)
    * 创建函数的新实例 (`Function::NewInstance`, `Function::NewInstanceWithSideEffectType`)
    * 调用函数 (`Function::Call`)
    * 设置函数名称 (`Function::SetName`)
    * 获取函数名称、推断名称和调试名称 (`GetName`, `GetInferredName`, `GetDebugName`)
    * 获取函数的脚本来源信息 (`GetScriptOrigin`, `GetScriptLineNumber`, `GetScriptColumnNumber`, `GetScriptStartPosition`, `ScriptId`)
    * 获取绑定函数的目标函数 (`GetBoundFunction`)
    * 判断函数是否是空操作函数 (`Experimental_IsNopFunction`)
    * 获取 `Function.prototype.toString()` 的结果 (`Function::FunctionProtoToString`)
* **其他类型操作:**
    * 获取 `Name` 对象的标识哈希值 (`Name::GetIdentityHash`)
    * 获取 `String` 对象的长度、是否为单字节编码、UTF-8 长度、并进行 UTF-8 编码写入 (`String::Length`, `String::IsOneByte`, `String::Utf8Length`, `String::WriteUtf8`, 等)
    * 判断 `String` 对象是否为外部字符串 (`String::IsExternal`, `String::IsExternalTwoByte`, `String::IsExternalOneByte`)
    * 将 `String` 对象内部化 (`String::InternalizeString`)
    * 获取 `Symbol` 和 `Private` 对象的描述或名称 (`Symbol::Description`, `Private::Name`)
    * 获取数值类型的值 (`Number::Value`, `Boolean::Value`, `Integer::Value`, `Int32::Value`, `Uint32::Value`)
    * 获取和设置对象的内部字段 (`InternalFieldCount`, `SlowGetInternalField`, `SetInternalField`, `SlowGetAlignedPointerFromInternalField`, `SetAlignedPointerInInternalField`, `SetAlignedPointerInInternalFields`)
    * 包装和解包 C++ 对象 (`Object::Wrap`, `Object::Unwrap`)
* **V8 环境初始化:**
    * 初始化平台 (`V8::InitializePlatform`)
    * 释放平台资源 (`V8::DisposePlatform`)
    * 初始化 V8 并进行构建配置检查 (`V8::Initialize`)

**与 JavaScript 的关系及举例说明:**

这些 C++ 函数是 V8 引擎暴露给外部的 API，它们直接对应或支持 JavaScript 的语言特性。以下是一些 JavaScript 示例：

1. **`GetConstructorName()`:**
   ```javascript
   const obj = {};
   console.log(obj.constructor.name); // 输出 "Object"

   class MyClass {}
   const myObj = new MyClass();
   console.log(myObj.constructor.name); // 输出 "MyClass"
   ```

2. **`SetIntegrityLevel()`:**
   ```javascript
   const obj = { a: 1 };
   Object.seal(obj); // 对应 IntegrityLevel::kSealed
   obj.b = 2; // 严格模式下会报错，非严格模式下静默失败
   delete obj.a; // 严格模式下会报错，非严格模式下静默失败

   const obj2 = { a: 1 };
   Object.freeze(obj2); // 对应 IntegrityLevel::kFrozen
   obj2.a = 2; // 严格模式下会报错，非严格模式下静默失败
   ```

3. **`Delete()`:**
   ```javascript
   const obj = { a: 1, b: 2 };
   delete obj.a;
   console.log(obj); // 输出 { b: 2 }

   const arr = [1, 2, 3];
   delete arr[1];
   console.log(arr); // 输出 [ 1, <1 empty item>, 3 ]
   ```

4. **`Has()` 和 `HasOwnProperty()`:**
   ```javascript
   const obj = { a: 1 };
   console.log('a' in obj); // 输出 true (检查原型链)
   console.log(obj.hasOwnProperty('a')); // 输出 true (仅检查自身属性)

   const arr = [1, 2, 3];
   console.log(1 in arr); // 输出 true (检查索引)
   ```

5. **`SetNativeDataProperty()` 和 `SetAccessorProperty()`:**
   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'x', {
       get() { return this._x; },
       set(value) { this._x = value; },
       enumerable: true,
       configurable: true
   });
   obj.x = 10;
   console.log(obj.x); // 输出 10
   ```

6. **`CallAsFunction()` 和 `CallAsConstructor()`:**
   ```javascript
   function greet(name) {
       console.log(`Hello, ${name}!`);
   }
   greet('World'); // 作为函数调用

   class MyClass {
       constructor(value) {
           this.value = value;
       }
   }
   const instance = new MyClass(5); // 作为构造函数调用
   ```

7. **`Function::Call()`:**
   ```javascript
   function add(a, b) {
       return a + b;
   }
   const result = add.call(null, 5, 3); // 调用函数并指定 `this` 和参数
   console.log(result); // 输出 8
   ```

8. **`String::Length()`:**
   ```javascript
   const str = "Hello";
   console.log(str.length); // 输出 5
   ```

9. **`Symbol::Description()`:**
   ```javascript
   const sym = Symbol('mySymbol');
   console.log(sym.description); // 输出 "mySymbol"
   ```

总而言之，这个代码文件是 V8 引擎 API 的重要组成部分，它提供了操作 JavaScript 对象和函数的基础能力，是连接 C++ 应用程序和 JavaScript 代码的桥梁。它确保了 V8 引擎的各种核心功能能够以结构化的方式被外部程序使用。

### 提示词
```
这是目录为v8/src/api/api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```
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
  if (!is_compiled_scope.is_compiled() &&
      !i::Compiler::Compile(i_isolate, i::handle(sfi, i_isolate),
                            i::Compiler::CLEAR_EXCEPTION, &is_compiled_scope)) {
    return false;
  }
  DCHECK(is_compiled_scope.is_compiled());
  // Since |sfi| can be GC'ed, we get it again.
  sfi = i::Cast<i::JSFunction>(*self)->shared();
  if (!sfi->HasBytecodeArray()) return false;
  i::Handle<i::BytecodeArray> bytecode_array(sfi->GetBytecodeArray(i_isolate),
                                             i_isolate);
  i::interpreter::BytecodeArrayIterator it(bytecode_array, 0);
  if (it.current_bytecode() != i::interpreter::Bytecode::kLdaUndefined) {
    return false;
  }
  it.Advance();
  DCHECK(!it.done());
  if (it.current_bytecode() != i::interpreter::Bytecode::kReturn) return false;
  it.Advance();
  DCHECK(it.done());
  return true;
}

MaybeLocal<String> v8::Function::FunctionProtoToString(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, Function, FunctionProtoToString);
  auto self = Utils::OpenHandle(this);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::CallBuiltin(i_isolate, i_isolate->function_to_string(),
                                self, 0, nullptr),
      &result);
  RETURN_ON_FAILED_EXECUTION(String);
  RETURN_ESCAPED(Local<String>::Cast(result));
}

int Name::GetIdentityHash() {
  return static_cast<int>(Utils::OpenDirectHandle(this)->EnsureHash());
}

int String::Length() const {
  return static_cast<int>(Utils::OpenDirectHandle(this)->length());
}

bool String::IsOneByte() const {
  return Utils::OpenDirectHandle(this)->IsOneByteRepresentation();
}

// Helpers for ContainsOnlyOneByteHelper
template <size_t size>
struct OneByteMask;
template <>
struct OneByteMask<4> {
  static const uint32_t value = 0xFF00FF00;
};
template <>
struct OneByteMask<8> {
  static const uint64_t value = 0xFF00'FF00'FF00'FF00;
};
static const uintptr_t kOneByteMask = OneByteMask<sizeof(uintptr_t)>::value;
static const uintptr_t kAlignmentMask = sizeof(uintptr_t) - 1;
static inline bool Unaligned(const uint16_t* chars) {
  return reinterpret_cast<const uintptr_t>(chars) & kAlignmentMask;
}

static inline const uint16_t* Align(const uint16_t* chars) {
  return reinterpret_cast<uint16_t*>(reinterpret_cast<uintptr_t>(chars) &
                                     ~kAlignmentMask);
}

class ContainsOnlyOneByteHelper {
 public:
  ContainsOnlyOneByteHelper() : is_one_byte_(true) {}
  ContainsOnlyOneByteHelper(const ContainsOnlyOneByteHelper&) = delete;
  ContainsOnlyOneByteHelper& operator=(const ContainsOnlyOneByteHelper&) =
      delete;
  bool Check(i::Tagged<i::String> string) {
    i::Tagged<i::ConsString> cons_string =
        i::String::VisitFlat(this, string, 0);
    if (cons_string.is_null()) return is_one_byte_;
    return CheckCons(cons_string);
  }
  void VisitOneByteString(const uint8_t* chars, int length) {
    // Nothing to do.
  }
  void VisitTwoByteString(const uint16_t* chars, int length) {
    // Accumulated bits.
    uintptr_t acc = 0;
    // Align to uintptr_t.
    const uint16_t* end = chars + length;
    while (Unaligned(chars) && chars != end) {
      acc |= *chars++;
    }
    // Read word aligned in blocks,
    // checking the return value at the end of each block.
    const uint16_t* aligned_end = Align(end);
    const int increment = sizeof(uintptr_t) / sizeof(uint16_t);
    const int inner_loops = 16;
    while (chars + inner_loops * increment < aligned_end) {
      for (int i = 0; i < inner_loops; i++) {
        acc |= *reinterpret_cast<const uintptr_t*>(chars);
        chars += increment;
      }
      // Check for early return.
      if ((acc & kOneByteMask) != 0) {
        is_one_byte_ = false;
        return;
      }
    }
    // Read the rest.
    while (chars != end) {
      acc |= *chars++;
    }
    // Check result.
    if ((acc & kOneByteMask) != 0) is_one_byte_ = false;
  }

 private:
  bool CheckCons(i::Tagged<i::ConsString> cons_string) {
    while (true) {
      // Check left side if flat.
      i::Tagged<i::String> left = cons_string->first();
      i::Tagged<i::ConsString> left_as_cons =
          i::String::VisitFlat(this, left, 0);
      if (!is_one_byte_) return false;
      // Check right side if flat.
      i::Tagged<i::String> right = cons_string->second();
      i::Tagged<i::ConsString> right_as_cons =
          i::String::VisitFlat(this, right, 0);
      if (!is_one_byte_) return false;
      // Standard recurse/iterate trick.
      if (!left_as_cons.is_null() && !right_as_cons.is_null()) {
        if (left->length() < right->length()) {
          CheckCons(left_as_cons);
          cons_string = right_as_cons;
        } else {
          CheckCons(right_as_cons);
          cons_string = left_as_cons;
        }
        // Check fast return.
        if (!is_one_byte_) return false;
        continue;
      }
      // Descend left in place.
      if (!left_as_cons.is_null()) {
        cons_string = left_as_cons;
        continue;
      }
      // Descend right in place.
      if (!right_as_cons.is_null()) {
        cons_string = right_as_cons;
        continue;
      }
      // Terminate.
      break;
    }
    return is_one_byte_;
  }
  bool is_one_byte_;
};

bool String::ContainsOnlyOneByte() const {
  auto str = Utils::OpenDirectHandle(this);
  if (str->IsOneByteRepresentation()) return true;
  ContainsOnlyOneByteHelper helper;
  return helper.Check(*str);
}

int String::Utf8Length(Isolate* v8_isolate) const {
  auto str = Utils::OpenHandle(this);
  str = i::String::Flatten(reinterpret_cast<i::Isolate*>(v8_isolate), str);
  int length = str->length();
  if (length == 0) return 0;
  i::DisallowGarbageCollection no_gc;
  i::String::FlatContent flat = str->GetFlatContent(no_gc);
  DCHECK(flat.IsFlat());
  int utf8_length = 0;
  if (flat.IsOneByte()) {
    for (uint8_t c : flat.ToOneByteVector()) {
      utf8_length += c >> 7;
    }
    utf8_length += length;
  } else {
    int last_character = unibrow::Utf16::kNoPreviousCharacter;
    for (uint16_t c : flat.ToUC16Vector()) {
      utf8_length += unibrow::Utf8::Length(c, last_character);
      last_character = c;
    }
  }
  return utf8_length;
}

size_t String::Utf8LengthV2(Isolate* v8_isolate) const {
  auto str = Utils::OpenHandle(this);
  return i::String::Utf8Length(reinterpret_cast<i::Isolate*>(v8_isolate), str);
}

namespace {
// Writes the flat content of a string to a buffer. This is done in two phases.
// The first phase calculates a pessimistic estimate (writable_length) on how
// many code units can be safely written without exceeding the buffer capacity
// and without leaving at a lone surrogate. The estimated number of code units
// is then written out in one go, and the reported byte usage is used to
// correct the estimate. This is repeated until the estimate becomes <= 0 or
// all code units have been written out. The second phase writes out code
// units until the buffer capacity is reached, would be exceeded by the next
// unit, or all code units have been written out.
template <typename Char>
static int WriteUtf8Impl(base::Vector<const Char> string, char* write_start,
                         int write_capacity, int options,
                         int* utf16_chars_read_out) {
  bool write_null = !(options & v8::String::NO_NULL_TERMINATION);
  bool replace_invalid_utf8 = (options & v8::String::REPLACE_INVALID_UTF8);
  char* current_write = write_start;
  const Char* read_start = string.begin();
  int read_index = 0;
  int read_length = string.length();
  int prev_char = unibrow::Utf16::kNoPreviousCharacter;
  // Do a fast loop where there is no exit capacity check.
  // Need enough space to write everything but one character.
  static_assert(unibrow::Utf16::kMaxExtraUtf8BytesForOneUtf16CodeUnit == 3);
  static const int kMaxSizePerChar = sizeof(Char) == 1 ? 2 : 3;
  while (read_index < read_length) {
    int up_to = read_length;
    if (write_capacity != -1) {
      int remaining_capacity =
          write_capacity - static_cast<int>(current_write - write_start);
      int writable_length =
          (remaining_capacity - kMaxSizePerChar) / kMaxSizePerChar;
      // Need to drop into slow loop.
      if (writable_length <= 0) break;
      up_to = std::min(up_to, read_index + writable_length);
    }
    // Write the characters to the stream.
    if (sizeof(Char) == 1) {
      // Simply memcpy if we only have ASCII characters.
      uint8_t char_mask = 0;
      for (int i = read_index; i < up_to; i++) char_mask |= read_start[i];
      if ((char_mask & 0x80) == 0) {
        int copy_length = up_to - read_index;
        memcpy(current_write, read_start + read_index, copy_length);
        current_write += copy_length;
        read_index = up_to;
      } else {
        for (; read_index < up_to; read_index++) {
          current_write += unibrow::Utf8::EncodeOneByte(
              current_write, static_cast<uint8_t>(read_start[read_index]));
          DCHECK(write_capacity == -1 ||
                 (current_write - write_start) <= write_capacity);
        }
      }
    } else {
      for (; read_index < up_to; read_index++) {
        uint16_t character = read_start[read_index];
        current_write += unibrow::Utf8::Encode(current_write, character,
                                               prev_char, replace_invalid_utf8);
        prev_char = character;
        DCHECK(write_capacity == -1 ||
               (current_write - write_start) <= write_capacity);
      }
    }
  }
  if (read_index < read_length) {
    DCHECK_NE(-1, write_capacity);
    // Aborted due to limited capacity. Check capacity on each iteration.
    int remaining_capacity =
        write_capacity - static_cast<int>(current_write - write_start);
    DCHECK_GE(remaining_capacity, 0);
    for (; read_index < read_length && remaining_capacity > 0; read_index++) {
      uint32_t character = read_start[read_index];
      int written = 0;
      // We can't use a local buffer here because Encode needs to modify
      // previous characters in the stream.  We know, however, that
      // exactly one character will be advanced.
      if (unibrow::Utf16::IsSurrogatePair(prev_char, character)) {
        written = unibrow::Utf8::Encode(current_write, character, prev_char,
                                        replace_invalid_utf8);
        DCHECK_EQ(written, 1);
      } else {
        // Use a scratch buffer to check the required characters.
        char temp_buffer[unibrow::Utf8::kMaxEncodedSize];
        // Encoding a surrogate pair to Utf8 always takes 4 bytes.
        static const int kSurrogatePairEncodedSize =
            static_cast<int>(unibrow::Utf8::kMaxEncodedSize);
        // For REPLACE_INVALID_UTF8, catch the case where we cut off in the
        // middle of a surrogate pair. Abort before encoding the pair instead.
        if (replace_invalid_utf8 &&
            remaining_capacity < kSurrogatePairEncodedSize &&
            unibrow::Utf16::IsLeadSurrogate(character) &&
            read_index + 1 < read_length &&
            unibrow::Utf16::IsTrailSurrogate(read_start[read_index + 1])) {
          write_null = false;
          break;
        }
        // Can't encode using prev_char as gcc has array bounds issues.
        written = unibrow::Utf8::Encode(temp_buffer, character,
                                        unibrow::Utf16::kNoPreviousCharacter,
                                        replace_invalid_utf8);
        if (written > remaining_capacity) {
          // Won't fit. Abort and do not null-terminate the result.
          write_null = false;
          break;
        }
        // Copy over the character from temp_buffer.
        for (int i = 0; i < written; i++) current_write[i] = temp_buffer[i];
      }

      current_write += written;
      remaining_capacity -= written;
      prev_char = character;
    }
  }

  // Write out number of utf16 characters written to the stream.
  if (utf16_chars_read_out != nullptr) *utf16_chars_read_out = read_index;

  // Only null-terminate if there's space.
  if (write_null && (write_capacity == -1 ||
                     (current_write - write_start) < write_capacity)) {
    *current_write++ = '\0';
  }
  return static_cast<int>(current_write - write_start);
}
}  // anonymous namespace

int String::WriteUtf8(Isolate* v8_isolate, char* buffer, int capacity,
                      int* nchars_ref, int options) const {
  auto str = Utils::OpenHandle(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, String, WriteUtf8);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  str = i::String::Flatten(i_isolate, str);
  i::DisallowGarbageCollection no_gc;
  i::String::FlatContent content = str->GetFlatContent(no_gc);
  if (content.IsOneByte()) {
    return WriteUtf8Impl<uint8_t>(content.ToOneByteVector(), buffer, capacity,
                                  options, nchars_ref);
  } else {
    return WriteUtf8Impl<uint16_t>(content.ToUC16Vector(), buffer, capacity,
                                   options, nchars_ref);
  }
}

template <typename CharType>
static inline int WriteHelper(i::Isolate* i_isolate, const String* string,
                              CharType* buffer, int start, int length,
                              int options) {
  API_RCS_SCOPE(i_isolate, String, Write);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  DCHECK(start >= 0 && length >= -1);
  auto str = Utils::OpenHandle(string);
  int end = start + length;
  if ((length == -1) || (static_cast<uint32_t>(length) > str->length() - start))
    end = str->length();
  if (end < 0) return 0;
  int write_length = end - start;
  if (start < end) i::String::WriteToFlat(*str, buffer, start, write_length);
  if (!(options & String::NO_NULL_TERMINATION) &&
      (length == -1 || write_length < length)) {
    buffer[write_length] = '\0';
  }
  return write_length;
}

int String::WriteOneByte(Isolate* v8_isolate, uint8_t* buffer, int start,
                         int length, int options) const {
  return WriteHelper(reinterpret_cast<i::Isolate*>(v8_isolate), this, buffer,
                     start, length, options);
}

int String::Write(Isolate* v8_isolate, uint16_t* buffer, int start, int length,
                  int options) const {
  return WriteHelper(reinterpret_cast<i::Isolate*>(v8_isolate), this, buffer,
                     start, length, options);
}

template <typename CharType>
static inline void WriteHelperV2(i::Isolate* i_isolate, const String* string,
                                 CharType* buffer, uint32_t offset,
                                 uint32_t length, int flags) {
  API_RCS_SCOPE(i_isolate, String, Write);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  DCHECK_LE(length, string->Length());
  DCHECK_LE(offset, string->Length() - length);

  auto str = Utils::OpenHandle(string);
  str = i::String::Flatten(i_isolate, str);
  i::String::WriteToFlat(*str, buffer, offset, length);
  if (flags & String::WriteFlags::kNullTerminate) {
    buffer[length] = '\0';
  }
}

void String::WriteV2(Isolate* v8_isolate, uint32_t offset, uint32_t length,
                     uint16_t* buffer, int flags) const {
  WriteHelperV2(reinterpret_cast<i::Isolate*>(v8_isolate), this, buffer, offset,
                length, flags);
}

void String::WriteOneByteV2(Isolate* v8_isolate, uint32_t offset,
                            uint32_t length, uint8_t* buffer, int flags) const {
  DCHECK(IsOneByte());
  WriteHelperV2(reinterpret_cast<i::Isolate*>(v8_isolate), this, buffer, offset,
                length, flags);
}

size_t String::WriteUtf8V2(Isolate* v8_isolate, char* buffer, size_t capacity,
                           int flags) const {
  auto str = Utils::OpenHandle(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, String, WriteUtf8);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::String::Utf8EncodingFlags i_flags;
  if (flags & String::WriteFlags::kNullTerminate) {
    i_flags |= i::String::Utf8EncodingFlag::kNullTerminate;
  }
  if (flags & String::WriteFlags::kReplaceInvalidUtf8) {
    i_flags |= i::String::Utf8EncodingFlag::kReplaceInvalid;
  }
  return i::String::WriteUtf8(i_isolate, str, buffer, capacity, i_flags);
}

namespace {

bool HasExternalStringResource(i::Tagged<i::String> string) {
  return i::StringShape(string).IsExternal() ||
         string->HasExternalForwardingIndex(kAcquireLoad);
}

v8::String::ExternalStringResourceBase* GetExternalResourceFromForwardingTable(
    i::Tagged<i::String> string, uint32_t raw_hash, bool* is_one_byte) {
  DCHECK(i::String::IsExternalForwardingIndex(raw_hash));
  const int index = i::String::ForwardingIndexValueBits::decode(raw_hash);
  // Note that with a shared heap the main and worker isolates all share the
  // same forwarding table.
  auto resource =
      i::Isolate::Current()->string_forwarding_table()->GetExternalResource(
          index, is_one_byte);
  DCHECK_NOT_NULL(resource);
  return resource;
}

}  // namespace

bool v8::String::IsExternal() const {
  return HasExternalStringResource(*Utils::OpenDirectHandle(this));
}

bool v8::String::IsExternalTwoByte() const {
  auto str = Utils::OpenDirectHandle(this);
  if (i::StringShape(*str).IsExternalTwoByte()) return true;
  uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
  if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
    bool is_one_byte;
    GetExternalResourceFromForwardingTable(*str, raw_hash_field, &is_one_byte);
    return !is_one_byte;
  }
  return false;
}

bool v8::String::IsExternalOneByte() const {
  auto str = Utils::OpenDirectHandle(this);
  if (i::StringShape(*str).IsExternalOneByte()) return true;
  uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
  if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
    bool is_one_byte;
    GetExternalResourceFromForwardingTable(*str, raw_hash_field, &is_one_byte);
    return is_one_byte;
  }
  return false;
}

Local<v8::String> v8::String::InternalizeString(Isolate* v8_isolate) {
  auto* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto str = Utils::OpenDirectHandle(this);
  return Utils::ToLocal(isolate->factory()->InternalizeString(str));
}

void v8::String::VerifyExternalStringResource(
    v8::String::ExternalStringResource* value) const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);
  const v8::String::ExternalStringResource* expected;

  if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
  }

  if (i::StringShape(str).IsExternalTwoByte()) {
    const void* resource = i::Cast<i::ExternalTwoByteString>(str)->resource();
    expected = reinterpret_cast<const ExternalStringResource*>(resource);
  } else {
    uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
    if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
      bool is_one_byte;
      auto resource = GetExternalResourceFromForwardingTable(
          str, raw_hash_field, &is_one_byte);
      if (!is_one_byte) {
        expected = reinterpret_cast<const ExternalStringResource*>(resource);
      }
    } else {
      expected = nullptr;
    }
  }
  CHECK_EQ(expected, value);
}

void v8::String::VerifyExternalStringResourceBase(
    v8::String::ExternalStringResourceBase* value, Encoding encoding) const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);
  const v8::String::ExternalStringResourceBase* expected;
  Encoding expectedEncoding;

  if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
  }

  if (i::StringShape(str).IsExternalOneByte()) {
    const void* resource = i::Cast<i::ExternalOneByteString>(str)->resource();
    expected = reinterpret_cast<const ExternalStringResourceBase*>(resource);
    expectedEncoding = ONE_BYTE_ENCODING;
  } else if (i::StringShape(str).IsExternalTwoByte()) {
    const void* resource = i::Cast<i::ExternalTwoByteString>(str)->resource();
    expected = reinterpret_cast<const ExternalStringResourceBase*>(resource);
    expectedEncoding = TWO_BYTE_ENCODING;
  } else {
    uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
    if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
      bool is_one_byte;
      expected = GetExternalResourceFromForwardingTable(str, raw_hash_field,
                                                        &is_one_byte);
      expectedEncoding = is_one_byte ? ONE_BYTE_ENCODING : TWO_BYTE_ENCODING;
    } else {
      expected = nullptr;
      expectedEncoding = str->IsOneByteRepresentation() ? ONE_BYTE_ENCODING
                                                        : TWO_BYTE_ENCODING;
    }
  }
  CHECK_EQ(expected, value);
  CHECK_EQ(expectedEncoding, encoding);
}

String::ExternalStringResource* String::GetExternalStringResourceSlow() const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);

  if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
  }

  if (i::StringShape(str).IsExternalTwoByte()) {
    Isolate* isolate = i::Internals::GetIsolateForSandbox(str.ptr());
    i::Address value =
        i::Internals::ReadExternalPointerField<i::kExternalStringResourceTag>(
            isolate, str.ptr(), i::Internals::kStringResourceOffset);
    return reinterpret_cast<String::ExternalStringResource*>(value);
  } else {
    uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
    if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
      bool is_one_byte;
      auto resource = GetExternalResourceFromForwardingTable(
          str, raw_hash_field, &is_one_byte);
      if (!is_one_byte) {
        return reinterpret_cast<ExternalStringResource*>(resource);
      }
    }
  }
  return nullptr;
}

void String::ExternalStringResource::UpdateDataCache() {
  DCHECK(IsCacheable());
  cached_data_ = data();
}

void String::ExternalStringResource::CheckCachedDataInvariants() const {
  DCHECK(IsCacheable() && cached_data_ != nullptr);
}

void String::ExternalOneByteStringResource::UpdateDataCache() {
  DCHECK(IsCacheable());
  cached_data_ = data();
}

void String::ExternalOneByteStringResource::CheckCachedDataInvariants() const {
  DCHECK(IsCacheable() && cached_data_ != nullptr);
}

String::ExternalStringResourceBase* String::GetExternalStringResourceBaseSlow(
    String::Encoding* encoding_out) const {
  i::DisallowGarbageCollection no_gc;
  ExternalStringResourceBase* resource = nullptr;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);

  if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
  }

  internal::Address string = str.ptr();
  int type = i::Internals::GetInstanceType(string) &
             i::Internals::kStringRepresentationAndEncodingMask;
  *encoding_out =
      static_cast<Encoding>(type & i::Internals::kStringEncodingMask);
  if (i::StringShape(str).IsExternalOneByte() ||
      i::StringShape(str).IsExternalTwoByte()) {
    Isolate* isolate = i::Internals::GetIsolateForSandbox(string);
    i::Address value =
        i::Internals::ReadExternalPointerField<i::kExternalStringResourceTag>(
            isolate, string, i::Internals::kStringResourceOffset);
    resource = reinterpret_cast<ExternalStringResourceBase*>(value);
  } else {
    uint32_t raw_hash_field = str->raw_hash_field();
    if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
      bool is_one_byte;
      resource = GetExternalResourceFromForwardingTable(str, raw_hash_field,
                                                        &is_one_byte);
      *encoding_out = is_one_byte ? Encoding::ONE_BYTE_ENCODING
                                  : Encoding::TWO_BYTE_ENCODING;
    }
  }
  return resource;
}

const v8::String::ExternalOneByteStringResource*
v8::String::GetExternalOneByteStringResource() const {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::String> str = *Utils::OpenDirectHandle(this);
  if (i::StringShape(str).IsExternalOneByte()) {
    return i::Cast<i::ExternalOneByteString>(str)->resource();
  } else if (i::IsThinString(str)) {
    str = i::Cast<i::ThinString>(str)->actual();
    if (i::StringShape(str).IsExternalOneByte()) {
      return i::Cast<i::ExternalOneByteString>(str)->resource();
    }
  }
  uint32_t raw_hash_field = str->raw_hash_field(kAcquireLoad);
  if (i::String::IsExternalForwardingIndex(raw_hash_field)) {
    bool is_one_byte;
    auto resource = GetExternalResourceFromForwardingTable(str, raw_hash_field,
                                                           &is_one_byte);
    if (is_one_byte) {
      return reinterpret_cast<ExternalOneByteStringResource*>(resource);
    }
  }
  return nullptr;
}

Local<Value> Symbol::Description(Isolate* v8_isolate) const {
  auto sym = Utils::OpenDirectHandle(this);
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return Utils::ToLocal(i::direct_handle(sym->description(), isolate));
}

Local<Value> Private::Name() const {
  const Symbol* sym = reinterpret_cast<const Symbol*>(this);
  auto i_sym = Utils::OpenDirectHandle(sym);
  // v8::Private symbols are created by API and are therefore writable, so we
  // can always recover an Isolate.
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*i_sym);
  return sym->Description(reinterpret_cast<Isolate*>(i_isolate));
}

double Number::Value() const {
  return i::Object::NumberValue(*Utils::OpenDirectHandle(this));
}

bool Boolean::Value() const {
  return i::IsTrue(*Utils::OpenDirectHandle(this));
}

int64_t Integer::Value() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(obj)) {
    return i::Smi::ToInt(obj);
  } else {
    return static_cast<int64_t>(i::Object::NumberValue(obj));
  }
}

int32_t Int32::Value() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(obj)) {
    return i::Smi::ToInt(obj);
  } else {
    return static_cast<int32_t>(i::Object::NumberValue(obj));
  }
}

uint32_t Uint32::Value() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(obj)) {
    return i::Smi::ToInt(obj);
  } else {
    return static_cast<uint32_t>(i::Object::NumberValue(obj));
  }
}

int v8::Object::InternalFieldCount() const {
  auto self = *Utils::OpenDirectHandle(this);
  if (!IsJSObject(self)) return 0;
  return i::Cast<i::JSObject>(self)->GetEmbedderFieldCount();
}

static V8_INLINE bool InternalFieldOK(i::DirectHandle<i::JSReceiver> obj,
                                      int index, const char* location) {
  return Utils::ApiCheck(
      IsJSObject(*obj) &&
          (index < i::Cast<i::JSObject>(*obj)->GetEmbedderFieldCount()),
      location, "Internal field out of bounds");
}

Local<Data> v8::Object::SlowGetInternalField(int index) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::GetInternalField()";
  if (!InternalFieldOK(obj, index, location)) return Local<Value>();
  i::Isolate* isolate = obj->GetIsolate();
  return ToApiHandle<Data>(i::direct_handle(
      i::Cast<i::JSObject>(*obj)->GetEmbedderField(index), isolate));
}

void v8::Object::SetInternalField(int index, v8::Local<Data> value) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::SetInternalField()";
  if (!InternalFieldOK(obj, index, location)) return;
  auto val = Utils::OpenDirectHandle(*value);
  i::Cast<i::JSObject>(obj)->SetEmbedderField(index, *val);
}

void* v8::Object::SlowGetAlignedPointerFromInternalField(v8::Isolate* isolate,
                                                         int index) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::GetAlignedPointerFromInternalField()";
  if (!InternalFieldOK(obj, index, location)) return nullptr;
  void* result;
  Utils::ApiCheck(
      i::EmbedderDataSlot(i::Cast<i::JSObject>(*obj), index)
          .ToAlignedPointer(reinterpret_cast<i::Isolate*>(isolate), &result),
      location, "Unaligned pointer");
  return result;
}

void* v8::Object::SlowGetAlignedPointerFromInternalField(int index) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::GetAlignedPointerFromInternalField()";
  if (!InternalFieldOK(obj, index, location)) return nullptr;
  void* result;
  Utils::ApiCheck(i::EmbedderDataSlot(i::Cast<i::JSObject>(*obj), index)
                      .ToAlignedPointer(obj->GetIsolate(), &result),
                  location, "Unaligned pointer");
  return result;
}

void v8::Object::SetAlignedPointerInInternalField(int index, void* value) {
  auto obj = Utils::OpenDirectHandle(this);
  const char* location = "v8::Object::SetAlignedPointerInInternalField()";
  if (!InternalFieldOK(obj, index, location)) return;

  i::DisallowGarbageCollection no_gc;
  Utils::ApiCheck(i::EmbedderDataSlot(i::Cast<i::JSObject>(*obj), index)
                      .store_aligned_pointer(obj->GetIsolate(), *obj, value),
                  location, "Unaligned pointer");
  DCHECK_EQ(value, GetAlignedPointerFromInternalField(index));
}

void v8::Object::SetAlignedPointerInInternalFields(int argc, int indices[],
                                                   void* values[]) {
  auto obj = Utils::OpenDirectHandle(this);
  if (!IsJSObject(*obj)) return;
  i::DisallowGarbageCollection no_gc;
  const char* location = "v8::Object::SetAlignedPointerInInternalFields()";
  auto js_obj = i::Cast<i::JSObject>(*obj);
  int nof_embedder_fields = js_obj->GetEmbedderFieldCount();
  for (int i = 0; i < argc; i++) {
    int index = indices[i];
    if (!Utils::ApiCheck(index < nof_embedder_fields, location,
                         "Internal field out of bounds")) {
      return;
    }
    void* value = values[i];
    Utils::ApiCheck(i::EmbedderDataSlot(js_obj, index)
                        .store_aligned_pointer(obj->GetIsolate(), *obj, value),
                    location, "Unaligned pointer");
    DCHECK_EQ(value, GetAlignedPointerFromInternalField(index));
  }
}

// static
void* v8::Object::Unwrap(v8::Isolate* isolate, i::Address wrapper_obj,
                         CppHeapPointerTagRange tag_range) {
  DCHECK_LE(tag_range.lower_bound, tag_range.upper_bound);
  return i::JSApiWrapper(
             i::Cast<i::JSObject>(i::Tagged<i::Object>(wrapper_obj)))
      .GetCppHeapWrappable(reinterpret_cast<i::Isolate*>(isolate), tag_range);
}

// static
void v8::Object::Wrap(v8::Isolate* isolate, i::Address wrapper_obj,
                      CppHeapPointerTag tag, void* wrappable) {
  return i::JSApiWrapper(
             i::Cast<i::JSObject>(i::Tagged<i::Object>(wrapper_obj)))
      .SetCppHeapWrappable(reinterpret_cast<i::Isolate*>(isolate), wrappable,
                           tag);
}

// --- E n v i r o n m e n t ---

void v8::V8::InitializePlatform(Platform* platform) {
  i::V8::InitializePlatform(platform);
}

void v8::V8::DisposePlatform() { i::V8::DisposePlatform(); }

bool v8::V8::Initialize(const int build_config) {
  const bool kEmbedderPointerCompression =
      (build_config & kPointerCompression) != 0;
  if (kEmbedderPointerCompression != COMPRESS_POINTERS_BOOL) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "pointer compression is %s while on V8 side it's %s.",
        kEmbedderPointerCompression ? "ENABLED" : "DISABLED",
        COMPRESS_POINTERS_BOOL ? "ENABLED" : "DISABLED");
  }

  const int kEmbedderSmiValueSize = (build_config & k31BitSmis) ? 31 : 32;
  if (kEmbedderSmiValueSize != internal::kSmiValueSize) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "Smi value size is %d while on V8 side it's %d.",
        kEmbedderSmiValueSize, internal::kSmiValueSize);
  }

  const bool kEmbedderSandbox = (build_config & kSandbox) != 0;
  if (kEmbedderSandbox != V8_ENABLE_SANDBOX_BOOL) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "sandbox is %s while on V8 side it's %s.",
        kEmbedderSandbox ? "ENABLED" : "DISABLED",
        V8_ENABLE_SANDBOX_BOOL ? "ENABLED" : "DISABLED");
  }

  const bool kEmbedderTargetOsIsAndroid =
      (build_config & kTargetOsIsAndroid) != 0;
#ifdef V8_TARGET_OS_ANDROID
  const bool kV8TargetOsIsAndroid = true;
#else
  const bool kV8TargetOsIsAndroid = false;
#endif
  if (kEmbedderTargetOsIsAndroid != kV8TargetOsIsAndroid) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "target OS is %s while on V8 side it's %s.",
        kEmbedderTargetOsIsAndroid ? "Android" : "not Android",
        kV8TargetOsIsAndroid ? "Android" : "not Android");
  }

  const bool kEmbedderEnableChecks = (build_config & kEnableChecks) != 0;
#ifdef V8_ENABLE_CHECKS
  const bool kV8EnableChe
```