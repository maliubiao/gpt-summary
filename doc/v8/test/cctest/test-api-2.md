Response: The user wants me to summarize the functionality of the C++ code snippet provided. This is the third part of a larger file. I need to identify the main features being tested in this portion of the code.

Looking at the code, I see several `THREADED_TEST` macros, each testing a specific aspect of the V8 API. These tests seem to focus on:

1. **Symbol properties:** How symbols can be used as object keys, their identity, description, and interaction with property attributes.
2. **Symbol template properties:** How symbols work with object templates.
3. **Private properties:** How private symbols can be used to create non-enumerable, non-inherited properties on objects and proxies.
4. **Global symbols:** How to create and retrieve global symbols.
5. **Well-known symbols:** Testing the availability and values of predefined symbols like `Symbol.iterator`.
6. **Global privates:** How to create and access global private symbols.
7. **Hidden properties:** Testing private symbols as "hidden" properties.
8. **External values:** How to wrap raw C++ pointers in V8 `External` objects.
9. **Global handles:** Testing the lifecycle and management of persistent handles.
10. **Global objects:** Testing the `v8::Global` smart pointer for handle management.
11. **Weak callbacks:** Testing the two-pass weak callback mechanism for garbage collection notifications.
12. **Global value map:** Testing the `v8::GlobalValueMap` for managing V8 objects with associated keys.
13. **Vector of globals:** How to use `std::vector` to store `v8::Global` objects.
14. **Handle equality:** Testing the equality operators for local and persistent handles.
15. **Script exceptions:** How to catch and inspect exceptions thrown from JavaScript code.
16. **Message handlers:** Testing how to register and receive notifications about JavaScript errors and exceptions.
17. **Message attributes:** Testing the different methods available on the `v8::Message` object to retrieve information about the error.
18. **Stack trace limit:** How to get and set the maximum number of stack frames captured in stack traces.
19. **Current stack trace:**  How to obtain the current stack trace programmatically.
20. **Get/Set property:** Basic tests for getting and setting properties on objects.
21. **Property attributes:** Testing how to define and retrieve property attributes like `ReadOnly`, `DontDelete`, and `DontEnum`.

For the JavaScript example, I can pick a feature related to symbols or private properties as they are quite unique to these APIs.
这个C++代码文件（`v8/test/cctest/test-api.cc`的第3部分）主要测试了 **V8 API 中关于符号（Symbols）、私有属性（Private Properties）、全局句柄（Global Handles）、弱回调（Weak Callbacks）、消息处理（Message Handling）和属性描述符（Property Descriptors）等功能**。

以下是代码中涵盖的一些主要功能点的归纳：

*   **符号 (Symbols)**:
    *   测试了符号的创建 (`v8::Symbol::New`)、描述 (`Description`)、唯一性（即使字符串相同，普通符号也不相等）、以及如何作为对象属性的键。
    *   测试了全局符号 (`v8::Symbol::For` 和 `v8::Symbol::ForApi`)，确保相同名称的全局符号在不同上下文中是相同的。
    *   测试了知名符号 (Well-Known Symbols)，例如 `Symbol.iterator` 等，并验证它们可以通过 `v8::Symbol::GetIterator` 等 API 获取，并且与 JavaScript 中的 `Symbol.iterator` 指向同一个对象。
    *   测试了符号作为属性时的行为，包括设置、获取、删除，以及在继承中的表现。
    *   测试了符号对象 (`v8::SymbolObject`) 的创建和属性。

*   **私有属性 (Private Properties)**:
    *   测试了私有属性的创建 (`v8::Private::New` 和 `v8::Private::ForApi`)。
    *   测试了如何使用私有属性作为对象和代理对象 (`v8::Proxy`) 的键，并验证私有属性的不可枚举性和非继承性。
    *   测试了私有属性的设置 (`SetPrivate`)、获取 (`GetPrivate`)、删除 (`DeletePrivate`) 和检查存在性 (`HasPrivate`)。

*   **全局句柄 (Global Handles)**:
    *   测试了持久句柄 (`v8::Persistent`) 的创建、重置和使用，以保持 V8 对象在垃圾回收期间存活。
    *   测试了 `v8::Global` 智能指针，它提供了更安全的全局句柄管理，并在超出作用域时自动释放。
    *   测试了将本地句柄升级为全局句柄，以及全局句柄之间的相等性比较。

*   **弱回调 (Weak Callbacks)**:
    *   测试了使用弱回调 (`SetWeak`) 来监听对象的垃圾回收事件。
    *   测试了两阶段弱回调机制，允许在对象即将被回收时执行两个不同的回调函数。
    *   测试了在弱回调函数中执行 JavaScript 代码的能力。

*   **外部值 (External Values)**:
    *   测试了将 C++ 指针包装成 `v8::External` 对象，以便在 JavaScript 中使用。

*   **消息处理 (Message Handling)**:
    *   测试了如何注册消息监听器 (`AddMessageListener`) 以捕获 JavaScript 中的错误和异常。
    *   测试了消息监听器接收到的 `v8::Message` 对象，并验证了其包含的错误信息，例如资源名称、行号等。
    *   测试了跨域脚本的错误消息处理。

*   **属性描述符 (Property Descriptors)**:
    *   测试了如何使用 `DefineOwnProperty` 设置属性的特性，例如 `ReadOnly`（只读）、`DontDelete`（不可删除）、`DontEnum`（不可枚举）。
    *   测试了如何使用 `GetPropertyAttributes` 获取属性的特性。

与 JavaScript 的功能有很强的关系，因为它测试了 V8 引擎暴露给 JavaScript 的 API 的 C++ 实现。

**JavaScript 示例**

与此 C++ 代码中测试的符号和私有属性相关的 JavaScript 功能示例：

```javascript
// 符号 (Symbols)
const mySymbol = Symbol('myDescription');
const obj = {};
obj[mySymbol] = '这是一个符号属性';

console.log(obj[mySymbol]); // 输出: 这是一个符号属性
console.log(Object.keys(obj)); // 输出: [] (符号属性不可枚举)
console.log(Object.getOwnPropertySymbols(obj)); // 输出: [ Symbol(myDescription) ]

const globalSymbol = Symbol.for('myGlobalSymbol');
const anotherGlobalSymbol = Symbol.for('myGlobalSymbol');
console.log(globalSymbol === anotherGlobalSymbol); // 输出: true

// 知名符号
const arr = [1, 2, 3];
const iterator = arr[Symbol.iterator]();
console.log(iterator.next()); // 输出: { value: 1, done: false }

// 私有属性 (使用 # 语法，但这在 C++ API 中对应的是 Private)
class MyClass {
  #privateField = 10;

  getPrivateField() {
    return this.#privateField;
  }
}

const instance = new MyClass();
console.log(instance.getPrivateField()); // 输出: 10
// console.log(instance.#privateField); // 报错: Private field '#privateField' must be declared in an enclosing class
```

这个 JavaScript 示例展示了符号作为对象属性的用法，其不可枚举性，以及全局符号的特性。同时也展示了 JavaScript 中私有属性的用法（虽然语法上与 C++ 的 `Private` 不同，但在概念上是对应的）。 C++ 代码中的测试确保了 V8 引擎正确地实现了这些 JavaScript 特性。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共18部分，请归纳一下它的功能
```

### 源代码
```
andleScope scope(isolate);

  Local<v8::String> str = v8_str("str1");
  int hash = str->GetIdentityHash();
  int hash1 = str->GetIdentityHash();
  CHECK_EQ(hash, hash1);
  i::heap::InvokeMajorGC(CcTest::heap());
  int hash3 = str->GetIdentityHash();
  CHECK_EQ(hash, hash3);

  Local<v8::String> str2 = v8_str("str1");
  int hash4 = str2->GetIdentityHash();
  CHECK_EQ(hash, hash4);
}


THREADED_TEST(SymbolProperties) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  v8::Local<v8::Symbol> sym1 = v8::Symbol::New(isolate);
  v8::Local<v8::Symbol> sym2 = v8::Symbol::New(isolate, v8_str("my-symbol"));
  v8::Local<v8::Symbol> sym3 = v8::Symbol::New(isolate, v8_str("sym3"));
  v8::Local<v8::Symbol> sym4 = v8::Symbol::New(isolate, v8_str("native"));

  i::heap::InvokeMajorGC(CcTest::heap());

  // Check basic symbol functionality.
  CHECK(sym1->IsSymbol());
  CHECK(sym2->IsSymbol());
  CHECK(!obj->IsSymbol());

  CHECK(sym1->Equals(env.local(), sym1).FromJust());
  CHECK(sym2->Equals(env.local(), sym2).FromJust());
  CHECK(!sym1->Equals(env.local(), sym2).FromJust());
  CHECK(!sym2->Equals(env.local(), sym1).FromJust());
  CHECK(sym1->StrictEquals(sym1));
  CHECK(sym2->StrictEquals(sym2));
  CHECK(!sym1->StrictEquals(sym2));
  CHECK(!sym2->StrictEquals(sym1));

  CHECK(sym2->Description(isolate)
            ->Equals(env.local(), v8_str("my-symbol"))
            .FromJust());

  v8::Local<v8::Value> sym_val = sym2;
  CHECK(sym_val->IsSymbol());
  CHECK(sym_val->Equals(env.local(), sym2).FromJust());
  CHECK(sym_val->StrictEquals(sym2));
  CHECK(v8::Symbol::Cast(*sym_val)->Equals(env.local(), sym2).FromJust());

  v8::Local<v8::Value> sym_obj = v8::SymbolObject::New(isolate, sym2);
  CHECK(sym_obj->IsSymbolObject());
  CHECK(!sym2->IsSymbolObject());
  CHECK(!obj->IsSymbolObject());
  CHECK(sym_obj->Equals(env.local(), sym2).FromJust());
  CHECK(!sym_obj->StrictEquals(sym2));
  CHECK(v8::SymbolObject::Cast(*sym_obj)
            ->Equals(env.local(), sym_obj)
            .FromJust());
  CHECK(v8::SymbolObject::Cast(*sym_obj)
            ->ValueOf()
            ->Equals(env.local(), sym2)
            .FromJust());

  // Make sure delete of a non-existent symbol property works.
  CHECK(obj->Delete(env.local(), sym1).FromJust());
  CHECK(!obj->Has(env.local(), sym1).FromJust());

  CHECK(
      obj->Set(env.local(), sym1, v8::Integer::New(isolate, 1503)).FromJust());
  CHECK(obj->Has(env.local(), sym1).FromJust());
  CHECK_EQ(1503, obj->Get(env.local(), sym1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(
      obj->Set(env.local(), sym1, v8::Integer::New(isolate, 2002)).FromJust());
  CHECK(obj->Has(env.local(), sym1).FromJust());
  CHECK_EQ(2002, obj->Get(env.local(), sym1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(v8::None, obj->GetPropertyAttributes(env.local(), sym1).FromJust());

  CHECK_EQ(0u,
           obj->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
  unsigned num_props =
      obj->GetPropertyNames(env.local()).ToLocalChecked()->Length();
  CHECK(obj->Set(env.local(), v8_str("bla"), v8::Integer::New(isolate, 20))
            .FromJust());
  CHECK_EQ(1u,
           obj->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
  CHECK_EQ(num_props + 1,
           obj->GetPropertyNames(env.local()).ToLocalChecked()->Length());

  i::heap::InvokeMajorGC(CcTest::heap());

  CHECK(obj->SetNativeDataProperty(env.local(), sym3, SymbolAccessorGetter,
                                   SymbolAccessorSetter)
            .FromJust());
  CHECK(obj->Get(env.local(), sym3).ToLocalChecked()->IsUndefined());
  CHECK(obj->Set(env.local(), sym3, v8::Integer::New(isolate, 42)).FromJust());
  CHECK(obj->Get(env.local(), sym3)
            .ToLocalChecked()
            ->Equals(env.local(), v8::Integer::New(isolate, 42))
            .FromJust());
  CHECK(obj->Get(env.local(), v8_str("accessor_sym3"))
            .ToLocalChecked()
            ->Equals(env.local(), v8::Integer::New(isolate, 42))
            .FromJust());

  CHECK(obj->SetNativeDataProperty(env.local(), sym4, SymbolAccessorGetter)
            .FromJust());
  CHECK(obj->Get(env.local(), sym4).ToLocalChecked()->IsUndefined());
  CHECK(obj->Set(env.local(), v8_str("accessor_native"),
                 v8::Integer::New(isolate, 123))
            .FromJust());
  CHECK_EQ(123, obj->Get(env.local(), sym4)
                    .ToLocalChecked()
                    ->Int32Value(env.local())
                    .FromJust());
  CHECK(obj->Set(env.local(), sym4, v8::Integer::New(isolate, 314)).FromJust());
  CHECK(obj->Get(env.local(), sym4)
            .ToLocalChecked()
            ->Equals(env.local(), v8::Integer::New(isolate, 314))
            .FromJust());
  CHECK(obj->Delete(env.local(), v8_str("accessor_native")).FromJust());

  // Add another property and delete it afterwards to force the object in
  // slow case.
  CHECK(
      obj->Set(env.local(), sym2, v8::Integer::New(isolate, 2008)).FromJust());
  CHECK_EQ(2002, obj->Get(env.local(), sym1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2008, obj->Get(env.local(), sym2)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2002, obj->Get(env.local(), sym1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2u,
           obj->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());

  CHECK(obj->Has(env.local(), sym1).FromJust());
  CHECK(obj->Has(env.local(), sym2).FromJust());
  CHECK(obj->Has(env.local(), sym3).FromJust());
  CHECK(obj->Has(env.local(), v8_str("accessor_sym3")).FromJust());
  CHECK(obj->Delete(env.local(), sym2).FromJust());
  CHECK(obj->Has(env.local(), sym1).FromJust());
  CHECK(!obj->Has(env.local(), sym2).FromJust());
  CHECK(obj->Has(env.local(), sym3).FromJust());
  CHECK(obj->Has(env.local(), v8_str("accessor_sym3")).FromJust());
  CHECK_EQ(2002, obj->Get(env.local(), sym1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(obj->Get(env.local(), sym3)
            .ToLocalChecked()
            ->Equals(env.local(), v8::Integer::New(isolate, 42))
            .FromJust());
  CHECK(obj->Get(env.local(), v8_str("accessor_sym3"))
            .ToLocalChecked()
            ->Equals(env.local(), v8::Integer::New(isolate, 42))
            .FromJust());
  CHECK_EQ(2u,
           obj->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());

  // Symbol properties are inherited.
  v8::Local<v8::Object> child = v8::Object::New(isolate);
  CHECK(child->SetPrototypeV2(env.local(), obj).FromJust());
  CHECK(child->Has(env.local(), sym1).FromJust());
  CHECK_EQ(2002, child->Get(env.local(), sym1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(obj->Get(env.local(), sym3)
            .ToLocalChecked()
            ->Equals(env.local(), v8::Integer::New(isolate, 42))
            .FromJust());
  CHECK(obj->Get(env.local(), v8_str("accessor_sym3"))
            .ToLocalChecked()
            ->Equals(env.local(), v8::Integer::New(isolate, 42))
            .FromJust());
  CHECK_EQ(0u,
           child->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
}


THREADED_TEST(SymbolTemplateProperties) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> foo = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::Name> name = v8::Symbol::New(isolate);
  CHECK(!name.IsEmpty());
  foo->PrototypeTemplate()->Set(name, v8::FunctionTemplate::New(isolate));
  v8::Local<v8::Object> new_instance =
      foo->InstanceTemplate()->NewInstance(env.local()).ToLocalChecked();
  CHECK(!new_instance.IsEmpty());
  CHECK(new_instance->Has(env.local(), name).FromJust());
}


THREADED_TEST(PrivatePropertiesOnProxies) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> target = CompileRun("({})").As<v8::Object>();
  v8::Local<v8::Object> handler = CompileRun("({})").As<v8::Object>();

  v8::Local<v8::Proxy> proxy =
      v8::Proxy::New(env.local(), target, handler).ToLocalChecked();

  v8::Local<v8::Private> priv1 = v8::Private::New(isolate);
  v8::Local<v8::Private> priv2 =
      v8::Private::New(isolate, v8_str("my-private"));

  i::heap::InvokeMajorGC(CcTest::heap());

  CHECK(priv2->Name()
            ->Equals(env.local(),
                     v8::String::NewFromUtf8Literal(isolate, "my-private"))
            .FromJust());

  // Make sure delete of a non-existent private symbol property works.
  proxy->DeletePrivate(env.local(), priv1).FromJust();
  CHECK(!proxy->HasPrivate(env.local(), priv1).FromJust());

  CHECK(proxy->SetPrivate(env.local(), priv1, v8::Integer::New(isolate, 1503))
            .FromJust());
  CHECK(proxy->HasPrivate(env.local(), priv1).FromJust());
  CHECK_EQ(1503, proxy->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(proxy->SetPrivate(env.local(), priv1, v8::Integer::New(isolate, 2002))
            .FromJust());
  CHECK(proxy->HasPrivate(env.local(), priv1).FromJust());
  CHECK_EQ(2002, proxy->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());

  CHECK_EQ(0u,
           proxy->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
  unsigned num_props =
      proxy->GetPropertyNames(env.local()).ToLocalChecked()->Length();
  CHECK(proxy
            ->Set(env.local(), v8::String::NewFromUtf8Literal(isolate, "bla"),
                  v8::Integer::New(isolate, 20))
            .FromJust());
  CHECK_EQ(1u,
           proxy->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
  CHECK_EQ(num_props + 1,
           proxy->GetPropertyNames(env.local()).ToLocalChecked()->Length());

  i::heap::InvokeMajorGC(CcTest::heap());

  // Add another property and delete it afterwards to force the object in
  // slow case.
  CHECK(proxy->SetPrivate(env.local(), priv2, v8::Integer::New(isolate, 2008))
            .FromJust());
  CHECK_EQ(2002, proxy->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2008, proxy->GetPrivate(env.local(), priv2)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2002, proxy->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(1u,
           proxy->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());

  CHECK(proxy->HasPrivate(env.local(), priv1).FromJust());
  CHECK(proxy->HasPrivate(env.local(), priv2).FromJust());
  CHECK(proxy->DeletePrivate(env.local(), priv2).FromJust());
  CHECK(proxy->HasPrivate(env.local(), priv1).FromJust());
  CHECK(!proxy->HasPrivate(env.local(), priv2).FromJust());
  CHECK_EQ(2002, proxy->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(1u,
           proxy->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());

  // Private properties are not inherited (for the time being).
  v8::Local<v8::Object> child = v8::Object::New(isolate);
  CHECK(child->SetPrototypeV2(env.local(), proxy).FromJust());
  CHECK(!child->HasPrivate(env.local(), priv1).FromJust());
  CHECK_EQ(0u,
           child->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
}


THREADED_TEST(PrivateProperties) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  v8::Local<v8::Private> priv1 = v8::Private::New(isolate);
  v8::Local<v8::Private> priv2 =
      v8::Private::New(isolate, v8_str("my-private"));

  i::heap::InvokeMajorGC(CcTest::heap());

  CHECK(priv2->Name()
            ->Equals(env.local(),
                     v8::String::NewFromUtf8Literal(isolate, "my-private"))
            .FromJust());

  // Make sure delete of a non-existent private symbol property works.
  obj->DeletePrivate(env.local(), priv1).FromJust();
  CHECK(!obj->HasPrivate(env.local(), priv1).FromJust());

  CHECK(obj->SetPrivate(env.local(), priv1, v8::Integer::New(isolate, 1503))
            .FromJust());
  CHECK(obj->HasPrivate(env.local(), priv1).FromJust());
  CHECK_EQ(1503, obj->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(obj->SetPrivate(env.local(), priv1, v8::Integer::New(isolate, 2002))
            .FromJust());
  CHECK(obj->HasPrivate(env.local(), priv1).FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());

  CHECK_EQ(0u,
           obj->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
  unsigned num_props =
      obj->GetPropertyNames(env.local()).ToLocalChecked()->Length();
  CHECK(obj->Set(env.local(), v8::String::NewFromUtf8Literal(isolate, "bla"),
                 v8::Integer::New(isolate, 20))
            .FromJust());
  CHECK_EQ(1u,
           obj->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
  CHECK_EQ(num_props + 1,
           obj->GetPropertyNames(env.local()).ToLocalChecked()->Length());

  i::heap::InvokeMajorGC(CcTest::heap());

  // Add another property and delete it afterwards to force the object in
  // slow case.
  CHECK(obj->SetPrivate(env.local(), priv2, v8::Integer::New(isolate, 2008))
            .FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2008, obj->GetPrivate(env.local(), priv2)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(1u,
           obj->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());

  CHECK(obj->HasPrivate(env.local(), priv1).FromJust());
  CHECK(obj->HasPrivate(env.local(), priv2).FromJust());
  CHECK(obj->DeletePrivate(env.local(), priv2).FromJust());
  CHECK(obj->HasPrivate(env.local(), priv1).FromJust());
  CHECK(!obj->HasPrivate(env.local(), priv2).FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), priv1)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(1u,
           obj->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());

  // Private properties are not inherited (for the time being).
  v8::Local<v8::Object> child = v8::Object::New(isolate);
  CHECK(child->SetPrototypeV2(env.local(), obj).FromJust());
  CHECK(!child->HasPrivate(env.local(), priv1).FromJust());
  CHECK_EQ(0u,
           child->GetOwnPropertyNames(env.local()).ToLocalChecked()->Length());
}


THREADED_TEST(GlobalSymbols) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<String> name = v8_str("my-symbol");
  v8::Local<v8::Symbol> glob = v8::Symbol::For(isolate, name);
  v8::Local<v8::Symbol> glob2 = v8::Symbol::For(isolate, name);
  CHECK(glob2->SameValue(glob));

  v8::Local<v8::Symbol> glob_api = v8::Symbol::ForApi(isolate, name);
  v8::Local<v8::Symbol> glob_api2 = v8::Symbol::ForApi(isolate, name);
  CHECK(glob_api2->SameValue(glob_api));
  CHECK(!glob_api->SameValue(glob));

  v8::Local<v8::Symbol> sym = v8::Symbol::New(isolate, name);
  CHECK(!sym->SameValue(glob));

  CompileRun("var sym2 = Symbol.for('my-symbol')");
  v8::Local<Value> sym2 =
      env->Global()->Get(env.local(), v8_str("sym2")).ToLocalChecked();
  CHECK(sym2->SameValue(glob));
  CHECK(!sym2->SameValue(glob_api));
}

THREADED_TEST(GlobalSymbolsNoContext) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<String> name = v8_str("my-symbol");
  v8::Local<v8::Symbol> glob = v8::Symbol::For(isolate, name);
  v8::Local<v8::Symbol> glob2 = v8::Symbol::For(isolate, name);
  CHECK(glob2->SameValue(glob));

  v8::Local<v8::Symbol> glob_api = v8::Symbol::ForApi(isolate, name);
  v8::Local<v8::Symbol> glob_api2 = v8::Symbol::ForApi(isolate, name);
  CHECK(glob_api2->SameValue(glob_api));
  CHECK(!glob_api->SameValue(glob));
}

static void CheckWellKnownSymbol(v8::Local<v8::Symbol>(*getter)(v8::Isolate*),
                                 const char* name) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Symbol> symbol = getter(isolate);
  std::string script = std::string("var sym = ") + name;
  CompileRun(script.c_str());
  v8::Local<Value> value =
      env->Global()->Get(env.local(), v8_str("sym")).ToLocalChecked();

  CHECK(!value.IsEmpty());
  CHECK(!symbol.IsEmpty());
  CHECK(value->SameValue(symbol));
}


THREADED_TEST(WellKnownSymbols) {
  CheckWellKnownSymbol(v8::Symbol::GetIterator, "Symbol.iterator");
  CheckWellKnownSymbol(v8::Symbol::GetAsyncIterator, "Symbol.asyncIterator");
  CheckWellKnownSymbol(v8::Symbol::GetUnscopables, "Symbol.unscopables");
  CheckWellKnownSymbol(v8::Symbol::GetHasInstance, "Symbol.hasInstance");
  CheckWellKnownSymbol(v8::Symbol::GetIsConcatSpreadable,
                       "Symbol.isConcatSpreadable");
  CheckWellKnownSymbol(v8::Symbol::GetMatch, "Symbol.match");
  CheckWellKnownSymbol(v8::Symbol::GetReplace, "Symbol.replace");
  CheckWellKnownSymbol(v8::Symbol::GetSearch, "Symbol.search");
  CheckWellKnownSymbol(v8::Symbol::GetSplit, "Symbol.split");
  CheckWellKnownSymbol(v8::Symbol::GetToPrimitive, "Symbol.toPrimitive");
  CheckWellKnownSymbol(v8::Symbol::GetToStringTag, "Symbol.toStringTag");
}


THREADED_TEST(GlobalPrivates) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<String> name = v8_str("my-private");
  v8::Local<v8::Private> glob = v8::Private::ForApi(isolate, name);
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  CHECK(obj->SetPrivate(env.local(), glob, v8::Integer::New(isolate, 3))
            .FromJust());

  v8::Local<v8::Private> glob2 = v8::Private::ForApi(isolate, name);
  CHECK(obj->HasPrivate(env.local(), glob2).FromJust());

  v8::Local<v8::Private> priv = v8::Private::New(isolate, name);
  CHECK(!obj->HasPrivate(env.local(), priv).FromJust());

  CompileRun("var intern = %CreatePrivateSymbol('my-private')");
  v8::Local<Value> intern =
      env->Global()->Get(env.local(), v8_str("intern")).ToLocalChecked();
  CHECK(!obj->Has(env.local(), intern).FromJust());
}

THREADED_TEST(HiddenProperties) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> obj = v8::Object::New(env->GetIsolate());
  v8::Local<v8::Private> key =
      v8::Private::ForApi(isolate, v8_str("api-test::hidden-key"));
  v8::Local<v8::String> empty = v8_str("");
  v8::Local<v8::String> prop_name = v8_str("prop_name");

  i::heap::InvokeMajorGC(CcTest::heap());

  // Make sure delete of a non-existent hidden value works
  obj->DeletePrivate(env.local(), key).FromJust();

  CHECK(obj->SetPrivate(env.local(), key, v8::Integer::New(isolate, 1503))
            .FromJust());
  CHECK_EQ(1503, obj->GetPrivate(env.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(obj->SetPrivate(env.local(), key, v8::Integer::New(isolate, 2002))
            .FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());

  i::heap::InvokeMajorGC(CcTest::heap());

  // Make sure we do not find the hidden property.
  CHECK(!obj->Has(env.local(), empty).FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(obj->Get(env.local(), empty).ToLocalChecked()->IsUndefined());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(
      obj->Set(env.local(), empty, v8::Integer::New(isolate, 2003)).FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2003, obj->Get(env.local(), empty)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());

  i::heap::InvokeMajorGC(CcTest::heap());

  // Add another property and delete it afterwards to force the object in
  // slow case.
  CHECK(obj->Set(env.local(), prop_name, v8::Integer::New(isolate, 2008))
            .FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2008, obj->Get(env.local(), prop_name)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  CHECK(obj->Delete(env.local(), prop_name).FromJust());
  CHECK_EQ(2002, obj->GetPrivate(env.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());

  i::heap::InvokeMajorGC(CcTest::heap());

  CHECK(obj->SetPrivate(env.local(), key, v8::Integer::New(isolate, 2002))
            .FromJust());
  CHECK(obj->DeletePrivate(env.local(), key).FromJust());
  CHECK(!obj->HasPrivate(env.local(), key).FromJust());
}


THREADED_TEST(Regress97784) {
  // Regression test for crbug.com/97784
  // Messing with the Object.prototype should not have effect on
  // hidden properties.
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  v8::Local<v8::Object> obj = v8::Object::New(env->GetIsolate());
  v8::Local<v8::Private> key =
      v8::Private::New(env->GetIsolate(), v8_str("hidden"));

  CompileRun(
      "set_called = false;"
      "Object.defineProperty("
      "    Object.prototype,"
      "    'hidden',"
      "    {get: function() { return 45; },"
      "     set: function() { set_called = true; }})");

  CHECK(!obj->HasPrivate(env.local(), key).FromJust());
  // Make sure that the getter and setter from Object.prototype is not invoked.
  // If it did we would have full access to the hidden properties in
  // the accessor.
  CHECK(
      obj->SetPrivate(env.local(), key, v8::Integer::New(env->GetIsolate(), 42))
          .FromJust());
  ExpectFalse("set_called");
  CHECK_EQ(42, obj->GetPrivate(env.local(), key)
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}


THREADED_TEST(External) {
  v8::HandleScope scope(CcTest::isolate());
  int x = 3;
  Local<v8::External> ext = v8::External::New(CcTest::isolate(), &x);
  LocalContext env;
  CHECK(env->Global()->Set(env.local(), v8_str("ext"), ext).FromJust());
  Local<Value> reext_obj = CompileRun("this.ext");
  v8::Local<v8::External> reext = reext_obj.As<v8::External>();
  int* ptr = static_cast<int*>(reext->Value());
  CHECK_EQ(3, x);
  *ptr = 10;
  CHECK_EQ(x, 10);

  {
    i::DirectHandle<i::Object> obj = v8::Utils::OpenDirectHandle(*ext);
    CHECK_EQ(i::Cast<i::HeapObject>(*obj)->map(),
             CcTest::heap()->external_map());
    CHECK(ext->IsExternal());
    CHECK(!CompileRun("new Set().add(this.ext)").IsEmpty());
    CHECK_EQ(i::Cast<i::HeapObject>(*obj)->map(),
             CcTest::heap()->external_map());
    CHECK(ext->IsExternal());
  }

  // Make sure unaligned pointers are wrapped properly.
  char* data = i::StrDup("0123456789");
  Local<v8::Value> zero = v8::External::New(CcTest::isolate(), &data[0]);
  Local<v8::Value> one = v8::External::New(CcTest::isolate(), &data[1]);
  Local<v8::Value> two = v8::External::New(CcTest::isolate(), &data[2]);
  Local<v8::Value> three = v8::External::New(CcTest::isolate(), &data[3]);

  char* char_ptr = reinterpret_cast<char*>(v8::External::Cast(*zero)->Value());
  CHECK_EQ('0', *char_ptr);
  char_ptr = reinterpret_cast<char*>(v8::External::Cast(*one)->Value());
  CHECK_EQ('1', *char_ptr);
  char_ptr = reinterpret_cast<char*>(v8::External::Cast(*two)->Value());
  CHECK_EQ('2', *char_ptr);
  char_ptr = reinterpret_cast<char*>(v8::External::Cast(*three)->Value());
  CHECK_EQ('3', *char_ptr);
  i::DeleteArray(data);
}


THREADED_TEST(GlobalHandle) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Persistent<String> global;
  {
    v8::HandleScope scope(isolate);
    global.Reset(isolate, v8_str("str"));
  }
  {
    v8::HandleScope scope(isolate);
    CHECK_EQ(3, v8::Local<String>::New(isolate, global)->Length());
  }
  global.Reset();
  {
    v8::HandleScope scope(isolate);
    global.Reset(isolate, v8_str("str"));
  }
  {
    v8::HandleScope scope(isolate);
    CHECK_EQ(3, v8::Local<String>::New(isolate, global)->Length());
  }
  global.Reset();
}


THREADED_TEST(ResettingGlobalHandle) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Persistent<String> global;
  {
    v8::HandleScope scope(isolate);
    global.Reset(isolate, v8_str("str"));
  }
  i::GlobalHandles* global_handles =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t initial_handle_count = global_handles->handles_count();
  {
    v8::HandleScope scope(isolate);
    CHECK_EQ(3, v8::Local<String>::New(isolate, global)->Length());
  }
  {
    v8::HandleScope scope(isolate);
    global.Reset(isolate, v8_str("longer"));
  }
  CHECK_EQ(global_handles->handles_count(), initial_handle_count);
  {
    v8::HandleScope scope(isolate);
    CHECK_EQ(6, v8::Local<String>::New(isolate, global)->Length());
  }
  global.Reset();
  CHECK_EQ(global_handles->handles_count(), initial_handle_count - 1);
}


THREADED_TEST(ResettingGlobalHandleToEmpty) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Persistent<String> global;
  {
    v8::HandleScope scope(isolate);
    global.Reset(isolate, v8_str("str"));
  }
  i::GlobalHandles* global_handles =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t initial_handle_count = global_handles->handles_count();
  {
    v8::HandleScope scope(isolate);
    CHECK_EQ(3, v8::Local<String>::New(isolate, global)->Length());
  }
  {
    v8::HandleScope scope(isolate);
    Local<String> empty;
    global.Reset(isolate, empty);
  }
  CHECK(global.IsEmpty());
  CHECK_EQ(global_handles->handles_count(), initial_handle_count - 1);
}


template <class T>
static v8::Global<T> PassUnique(v8::Global<T> unique) {
  return unique.Pass();
}


template <class T>
static v8::Global<T> ReturnUnique(v8::Isolate* isolate,
                                  const v8::Persistent<T>& global) {
  v8::Global<String> unique(isolate, global);
  return unique.Pass();
}


THREADED_TEST(Global) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Persistent<String> global;
  {
    v8::HandleScope scope(isolate);
    global.Reset(isolate, v8_str("str"));
  }
  i::GlobalHandles* global_handles =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t initial_handle_count = global_handles->handles_count();
  {
    v8::Global<String> unique(isolate, global);
    CHECK_EQ(initial_handle_count + 1, global_handles->handles_count());
    // Test assignment via Pass
    {
      v8::Global<String> copy = unique.Pass();
      CHECK(unique.IsEmpty());
      CHECK(copy == global);
      CHECK_EQ(initial_handle_count + 1, global_handles->handles_count());
      unique = copy.Pass();
    }
    // Test ctor via Pass
    {
      v8::Global<String> copy(unique.Pass());
      CHECK(unique.IsEmpty());
      CHECK(copy == global);
      CHECK_EQ(initial_handle_count + 1, global_handles->handles_count());
      unique = copy.Pass();
    }
    // Test pass through function call
    {
      v8::Global<String> copy = PassUnique(unique.Pass());
      CHECK(unique.IsEmpty());
      CHECK(copy == global);
      CHECK_EQ(initial_handle_count + 1, global_handles->handles_count());
      unique = copy.Pass();
    }
    CHECK_EQ(initial_handle_count + 1, global_handles->handles_count());
  }
  // Test pass from function call
  {
    v8::Global<String> unique = ReturnUnique(isolate, global);
    CHECK(unique == global);
    CHECK_EQ(initial_handle_count + 1, global_handles->handles_count());
  }
  CHECK_EQ(initial_handle_count, global_handles->handles_count());
  global.Reset();
}


namespace {

class TwoPassCallbackData;
void FirstPassCallback(const v8::WeakCallbackInfo<TwoPassCallbackData>& data);
void SecondPassCallback(const v8::WeakCallbackInfo<TwoPassCallbackData>& data);

struct GCCallbackMetadata {
  int instance_counter = 0;
  int depth = 0;
  v8::Persistent<v8::Context> context;

  GCCallbackMetadata() {
    auto isolate = CcTest::isolate();
    v8::HandleScope handle_scope(isolate);
    context.Reset(isolate, CcTest::NewContext());
  }

  ~GCCallbackMetadata() {
    CHECK_EQ(0, instance_counter);
    CHECK_EQ(0, depth);
  }

  struct DepthCheck {
    explicit DepthCheck(GCCallbackMetadata* counters) : counters(counters) {
      CHECK_EQ(counters->depth, 0);
      counters->depth++;
    }

    ~DepthCheck() {
      counters->depth--;
      CHECK_EQ(counters->depth, 0);
    }

    GCCallbackMetadata* counters;
  };
};

class TwoPassCallbackData {
 public:
  TwoPassCallbackData(v8::Isolate* isolate, GCCallbackMetadata* metadata)
      : first_pass_called_(false),
        second_pass_called_(false),
        trigger_gc_(false),
        metadata_(metadata) {
    HandleScope scope(isolate);
    v8::base::ScopedVector<char> buffer(40);
    v8::base::SNPrintF(buffer, "%p", static_cast<void*>(this));
    auto string =
        v8::String::NewFromUtf8(isolate, buffer.begin()).ToLocalChecked();
    cell_.Reset(isolate, string);
    metadata_->instance_counter++;
  }

  ~TwoPassCallbackData() {
    CHECK(first_pass_called_);
    CHECK(second_pass_called_);
    CHECK(cell_.IsEmpty());
    metadata_->instance_counter--;
  }

  void FirstPass() {
    CHECK(!first_pass_called_);
    CHECK(!second_pass_called_);
    CHECK(!cell_.IsEmpty());
    cell_.Reset();
    first_pass_called_ = true;
  }

  void SecondPass(v8::Isolate* isolate) {
    ApiTestFuzzer::Fuzz();

    GCCallbackMetadata::DepthCheck depth_check(metadata_);
    CHECK(first_pass_called_);
    CHECK(!second_pass_called_);
    CHECK(cell_.IsEmpty());
    second_pass_called_ = true;

    GCCallbackMetadata* metadata = metadata_;
    bool trigger_gc = trigger_gc_;
    delete this;

    {
      // Make sure that running JS works inside the second pass callback.
      v8::HandleScope handle_scope(isolate);
      v8::Context::Scope context_scope(metadata->context.Get(isolate));
      v8::Local<v8::Value> value = CompileRun("(function() { return 42 })()");
      CHECK(value->IsInt32());
      CHECK_EQ(value.As<v8::Int32>()->Value(), 42);
    }

    if (!trigger_gc) return;
    auto data_2 = new TwoPassCallbackData(isolate, metadata);
    data_2->SetWeak();
    i::heap::InvokeMajorGC(CcTest::heap());
  }

  void SetWeak() {
    cell_.SetWeak(this, FirstPassCallback, v8::WeakCallbackType::kParameter);
  }

  void MarkTriggerGc() { trigger_gc_ = true; }

 private:
  bool first_pass_called_;
  bool second_pass_called_;
  bool trigger_gc_;
  v8::Global<v8::String> cell_;
  GCCallbackMetadata* metadata_;
};


void SecondPassCallback(const v8::WeakCallbackInfo<TwoPassCallbackData>& data) {
  data.GetParameter()->SecondPass(data.GetIsolate());
}


void FirstPassCallback(const v8::WeakCallbackInfo<TwoPassCallbackData>& data) {
  data.GetParameter()->FirstPass();
  data.SetSecondPassCallback(SecondPassCallback);
}

}  // namespace


TEST(TwoPassPhantomCallbacks) {
  auto isolate = CcTest::isolate();
  GCCallbackMetadata metadata;
  const size_t kLength = 20;
  for (size_t i = 0; i < kLength; ++i) {
    auto data = new TwoPassCallbackData(isolate, &metadata);
    data->SetWeak();
  }
  CHECK_EQ(static_cast<int>(kLength), metadata.instance_counter);
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  EmptyMessageQueues(isolate);
}


TEST(TwoPassPhantomCallbacksNestedGc) {
  auto isolate = CcTest::isolate();
  GCCallbackMetadata metadata;
  const size_t kLength = 20;
  TwoPassCallbackData* array[kLength];
  for (size_t i = 0; i < kLength; ++i) {
    array[i] = new TwoPassCallbackData(isolate, &metadata);
    array[i]->SetWeak();
  }
  array[5]->MarkTriggerGc();
  array[10]->MarkTriggerGc();
  array[15]->MarkTriggerGc();
  CHECK_EQ(static_cast<int>(kLength), metadata.instance_counter);
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  EmptyMessageQueues(isolate);
}

// The string creation API methods forbid executing JS code while they are
// on the stack. Make sure that when such a string creation triggers GC,
// the second pass callback can still execute JS as per its API contract.
TEST(TwoPassPhantomCallbacksTriggeredByStringAlloc) {
  auto isolate = CcTest::isolate();
  GCCallbackMetadata metadata;
  auto data = new TwoPassCallbackData(isolate, &metadata);
  data->SetWeak();
  CHECK_EQ(metadata.instance_counter, 1);

  v8::base::ScopedVector<uint8_t> source(200000);

  // In the rest of this test, we need to invoke GC without stack, otherwise the
  // weak references may not be cleared because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  // Creating a few large strings suffices to trigger GC.
  while (metadata.instance_counter == 1) {
    v8::HandleScope handle_scope(isolate);
    USE(v8::String::NewFromOneByte(isolate, source.begin(),
                                   v8::NewStringType::kNormal,
                                   static_cast<int>(source.size())));
  }
  EmptyMessageQueues(isolate);
}

namespace {

void* IntKeyToVoidPointer(int key) { return reinterpret_cast<void*>(key << 1); }


Local<v8::Object> NewObjectForIntKey(
    v8::Isolate* isolate, const v8::Global<v8::ObjectTemplate>& templ,
    int key) {
  auto local = Local<v8::ObjectTemplate>::New(isolate, templ);
  auto obj = local->NewInstance(isolate->GetCurrentContext()).ToLocalChecked();
  obj->SetAlignedPointerInInternalField(0, IntKeyToVoidPointer(key));
  return obj;
}


template <typename K, typename V>
class PhantomStdMapTraits : public v8::StdMapTraits<K, V> {
 public:
  using MapType = typename v8::GlobalValueMap<K, V, PhantomStdMapTraits<K, V>>;
  static const v8::PersistentContainerCallbackType kCallbackType =
      v8::kWeakWithInternalFields;
  struct WeakCallbackDataType {
    MapType* map;
    K key;
  };
  static WeakCallbackDataType* WeakCallbackParameter(MapType* map, const K& key,
                                                     Local<V> value) {
    WeakCallbackDataType* data = new WeakCallbackDataType;
    data->map = map;
    data->key = key;
    return data;
  }
  static MapType* MapFromWeakCallbackInfo(
      const v8::WeakCallbackInfo<WeakCallbackDataType>& data) {
    return data.GetParameter()->map;
  }
  static K KeyFromWeakCallbackInfo(
      const v8::WeakCallbackInfo<WeakCallbackDataType>& data) {
    return data.GetParameter()->key;
  }
  static void DisposeCallbackData(WeakCallbackDataType* data) { delete data; }
  static void Dispose(v8::Isolate* isolate, v8::Global<V> value, K key) {
    CHECK_EQ(IntKeyToVoidPointer(key),
             v8::Object::GetAlignedPointerFromInternalField(value, 0));
  }
  static void OnWeakCallback(
      const v8::WeakCallbackInfo<WeakCallbackDataType>&) {}
  static void DisposeWeak(
      const v8::WeakCallbackInfo<WeakCallbackDataType>& info) {
    K key = KeyFromWeakCallbackInfo(info);
    CHECK_EQ(IntKeyToVoidPointer(key), info.GetInternalField(0));
    DisposeCallbackData(info.GetParameter());
  }
};


template <typename Map>
void TestGlobalValueMap() {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::Global<ObjectTemplate> templ;
  {
    HandleScope scope(isolate);
    auto t = ObjectTemplate::New(isolate);
    t->SetInternalFieldCount(1);
    templ.Reset(isolate, t);
  }
  Map map(isolate);
  i::GlobalHandles* global_handles =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t initial_handle_count = global_handles->handles_count();
  CHECK_EQ(0, static_cast<int>(map.Size()));
  {
    HandleScope scope(isolate);
    Local<v8::Object> obj = map.Get(7);
    CHECK(obj.IsEmpty());
    Local<v8::Object> expected = v8::Object::New(isolate);
    map.Set(7, expected);
    CHECK_EQ(1, static_cast<int>(map.Size()));
    obj = map.Get(7);
    CHECK(expected->Equals(env.local(), obj).FromJust());
    {
      typename Map::PersistentValueReference ref = map.GetReference(7);
      CHECK(expected->Equals(env.local(), ref.NewLocal(isolate)).FromJust());
    }
    v8::Global<v8::Object> removed = map.Remove(7);
    CHECK_EQ(0, static_cast<int>(map.Size()));
    CHECK(expected == removed);
    removed = map.Remove(7);
    CHECK(removed.IsEmpty());
    map.Set(8, expected);
    CHECK_EQ(1, static_cast<int>(map.Size()));
    map.Set(8, expected);
    CHECK_EQ(1, static_cast<int>(map.Size()));
    {
      typename Map::PersistentValueReference ref;
      Local<v8::Object> expected2 = NewObjectForIntKey(isolate, templ, 8);
      removed = map.Set(8, v8::Global<v8::Object>(isolate, expected2), &ref);
      CHECK_EQ(1, static_cast<int>(map.Size()));
      CHECK(expected == removed);
      CHECK(expected2->Equals(env.local(), ref.NewLocal(isolate)).FromJust());
    }
  }
  CHECK_EQ(initial_handle_count + 1, global_handles->handles_count());
  if (map.IsWeak()) {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  } else {
    map.Clear();
  }
  CHECK_EQ(0, static_cast<int>(map.Size()));
  CHECK_EQ(initial_handle_count, global_handles->handles_count());
  {
    HandleScope scope(isolate);
    Local<v8::Object> value = NewObjectForIntKey(isolate, templ, 9);
    map.Set(9, value);
    map.Clear();
  }
  CHECK_EQ(0, static_cast<int>(map.Size()));
  CHECK_EQ(initial_handle_count, global_handles->handles_count());
}

}  // namespace


TEST(GlobalValueMap) {
  // Default case, w/o weak callbacks:
  TestGlobalValueMap<v8::StdGlobalValueMap<int, v8::Object>>();

  // Custom traits with weak callbacks:
  using WeakMap =
      v8::GlobalValueMap<int, v8::Object, PhantomStdMapTraits<int, v8::Object>>;
  TestGlobalValueMap<WeakMap>();
}

TEST(VectorOfGlobals) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::GlobalHandles* global_handles =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t handle_count = global_handles->handles_count();
  HandleScope scope(isolate);

  std::vector<v8::Global<v8::Object>> vector;

  Local<v8::Object> obj1 = v8::Object::New(isolate);
  Local<v8::Object> obj2 = v8::Object::New(isolate);
  v8::Global<v8::Object> obj3(isolate, v8::Object::New(isolate));

  CHECK(vector.empty());
  CHECK_EQ(0, static_cast<int>(vector.size()));

  vector.reserve(3);
  CHECK(vector.empty());

  vector.emplace_back(isolate, obj1);
  vector.emplace_back(isolate, obj2);
  vector.emplace_back(isolate, obj1);
  vector.emplace_back(obj3.Pass());
  vector.emplace_back(isolate, obj1);

  CHECK(!vector.empty());
  CHECK_EQ(5, static_cast<int>(vector.size()));
  CHECK(obj3.IsEmpty());
  CHECK(obj1->Equals(env.local(), vector[0].Get(isolate)).FromJust());
  CHECK(obj1->Equals(env.local(), vector[2].Get(isolate)).FromJust());
  CHECK(obj1->Equals(env.local(), vector[4].Get(isolate)).FromJust());
  CHECK(obj2->Equals(env.local(), vector[1].Get(isolate)).FromJust());

  CHECK_EQ(5 + handle_count, global_handles->handles_count());

  vector.clear();
  CHECK(vector.empty());
  CHECK_EQ(0, static_cast<int>(vector.size()));
  CHECK_EQ(handle_count, global_handles->handles_count());
}

THREADED_TEST(GlobalHandleUpcast) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<String> local = v8::Local<String>::New(isolate, v8_str("str"));
  v8::Persistent<String> global_string(isolate, local);
  v8::Persistent<Value>& global_value =
      v8::Persistent<Value>::Cast(global_string);
  CHECK(v8::Local<v8::Value>::New(isolate, global_value)->IsString());
  CHECK(global_string == v8::Persistent<String>::Cast(global_value));
  global_string.Reset();
}


THREADED_TEST(HandleEquality) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Persistent<String> global1;
  v8::Persistent<String> global2;
  {
    v8::HandleScope scope(isolate);
    global1.Reset(isolate, v8_str("str"));
    global2.Reset(isolate, v8_str("str2"));
  }
  CHECK(global1 == global1);
  CHECK(!(global1 != global1));
  {
    v8::HandleScope scope(isolate);
    Local<String> local1 = Local<String>::New(isolate, global1);
    Local<String> local2 = Local<String>::New(isolate, global2);

    CHECK(global1 == local1);
    CHECK(!(global1 != local1));
    CHECK(local1 == global1);
    CHECK(!(local1 != global1));

    CHECK(!(global1 == local2));
    CHECK(global1 != local2);
    CHECK(!(local2 == global1));
    CHECK(local2 != global1);

    CHECK(!(local1 == local2));
    CHECK(local1 != local2);

    Local<String> anotherLocal1 = Local<String>::New(isolate, global1);
    CHECK(local1 == anotherLocal1);
    CHECK(!(local1 != anotherLocal1));
  }
  global1.Reset();
  global2.Reset();
}

THREADED_TEST(HandleEqualityPrimitives) {
  v8::HandleScope scope(CcTest::isolate());
  // Local::operator== works like strict equality except for primitives.
  CHECK_NE(v8_str("str"), v8_str("str"));
  CHECK_NE(v8::Number::New(CcTest::isolate(), 0.5),
           v8::Number::New(CcTest::isolate(), 0.5));
  CHECK_EQ(v8::Number::New(CcTest::isolate(), 1),
           v8::Number::New(CcTest::isolate(), 1));
}

THREADED_TEST(LocalHandle) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<String> local =
      v8::Local<String>::New(CcTest::isolate(), v8_str("str"));
  CHECK_EQ(3, local->Length());
}


class WeakCallCounter {
 public:
  explicit WeakCallCounter(int id) : id_(id), number_of_weak_calls_(0) {}
  int id() { return id_; }
  void increment() { number_of_weak_calls_++; }
  int NumberOfWeakCalls() { return number_of_weak_calls_; }

 private:
  int id_;
  int number_of_weak_calls_;
};


template <typename T>
struct WeakCallCounterAndPersistent {
  explicit WeakCallCounterAndPersistent(WeakCallCounter* counter)
      : counter(counter) {}
  WeakCallCounter* counter;
  v8::Persistent<T> handle;
};


template <typename T>
static void WeakPointerCallback(
    const v8::WeakCallbackInfo<WeakCallCounterAndPersistent<T>>& data) {
  CHECK_EQ(1234, data.GetParameter()->counter->id());
  data.GetParameter()->counter->increment();
  data.GetParameter()->handle.Reset();
}

THREADED_TEST(ScriptException) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<Script> script = v8_compile("throw 'panama!';");
  v8::TryCatch try_catch(env->GetIsolate());
  v8::MaybeLocal<Value> result = script->Run(env.local());
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(env->GetIsolate(), try_catch.Exception());
  CHECK_EQ(0, strcmp(*exception_value, "panama!"));
}

bool message_received;


static void check_message_0(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  CHECK_EQ(5.76, data->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  CHECK(!message->IsSharedCrossOrigin());
  message_received = true;
}


THREADED_TEST(MessageHandler0) {
  message_received = false;
  v8::HandleScope scope(CcTest::isolate());
  CHECK(!message_received);
  LocalContext context;
  CcTest::isolate()->AddMessageListener(check_message_0, v8_num(5.76));
  v8::Local<v8::Script> script =
      CompileWithOrigin("throw 'error'", "6.75", false);
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  CcTest::isolate()->RemoveMessageListeners(check_message_0);
}


static void check_message_1(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  CHECK(data->IsNumber());
  CHECK_EQ(1337,
           data->Int32Value(CcTest::isolate()->GetCurrentContext()).FromJust());
  CHECK(!message->IsSharedCrossOrigin());
  message_received = true;
}


TEST(MessageHandler1) {
  message_received = false;
  v8::HandleScope scope(CcTest::isolate());
  CHECK(!message_received);
  CcTest::isolate()->AddMessageListener(check_message_1);
  LocalContext context;
  CompileRun("throw 1337;");
  CHECK(message_received);
  // clear out the message listener
  CcTest::isolate()->RemoveMessageListeners(check_message_1);
}


static void check_message_2(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  LocalContext context;
  CHECK(data->IsObject());
  v8::Local<v8::Value> hidden_property =
      v8::Object::Cast(*data)
          ->GetPrivate(
              context.local(),
              v8::Private::ForApi(CcTest::isolate(), v8_str("hidden key")))
          .ToLocalChecked();
  CHECK(v8_str("hidden value")
            ->Equals(context.local(), hidden_property)
            .FromJust());
  CHECK(!message->IsSharedCrossOrigin());
  message_received = true;
}


TEST(MessageHandler2) {
  message_received = false;
  v8::HandleScope scope(CcTest::isolate());
  CHECK(!message_received);
  CcTest::isolate()->AddMessageListener(check_message_2);
  LocalContext context;
  v8::Local<v8::Value> error = v8::Exception::Error(v8_str("custom error"));
  v8::Object::Cast(*error)
      ->SetPrivate(context.local(),
                   v8::Private::ForApi(CcTest::isolate(), v8_str("hidden key")),
                   v8_str("hidden value"))
      .FromJust();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("error"), error)
            .FromJust());
  CompileRun("throw error;");
  CHECK(message_received);
  // clear out the message listener
  CcTest::isolate()->RemoveMessageListeners(check_message_2);
}


static void check_message_3(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  CHECK(message->IsSharedCrossOrigin());
  CHECK(message->GetScriptOrigin().Options().IsSharedCrossOrigin());
  CHECK(message->GetScriptOrigin().Options().IsOpaque());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  CHECK_EQ(7.40, message->GetScriptOrigin()
                     .SourceMapUrl()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  message_received = true;
}


TEST(MessageHandler3) {
  message_received = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  CHECK(!message_received);
  isolate->AddMessageListener(check_message_3);
  LocalContext context;
  v8::ScriptOrigin origin =
      v8::ScriptOrigin(v8_str("6.75"), 1, 2, true, -1, v8_str("7.40"), true);
  v8::Local<v8::Script> script =
      Script::Compile(context.local(), v8_str("throw 'error'"), &origin)
          .ToLocalChecked();
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  isolate->RemoveMessageListeners(check_message_3);
}


static void check_message_4(v8::Local<v8::Message> message,
                            v8::Local<Value> data) {
  CHECK(!message->IsSharedCrossOrigin());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  message_received = true;
}


TEST(MessageHandler4) {
  message_received = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  CHECK(!message_received);
  isolate->AddMessageListener(check_message_4);
  LocalContext context;
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("6.75"), 1, 2, false);
  v8::Local<v8::Script> script =
      Script::Compile(context.local(), v8_str("throw 'error'"), &origin)
          .ToLocalChecked();
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  isolate->RemoveMessageListeners(check_message_4);
}


static void check_message_5a(v8::Local<v8::Message> message,
                             v8::Local<Value> data) {
  CHECK(message->IsSharedCrossOrigin());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  message_received = true;
}


static void check_message_5b(v8::Local<v8::Message> message,
                             v8::Local<Value> data) {
  CHECK(!message->IsSharedCrossOrigin());
  CHECK_EQ(6.75, message->GetScriptOrigin()
                     .ResourceName()
                     ->NumberValue(CcTest::isolate()->GetCurrentContext())
                     .FromJust());
  message_received = true;
}


TEST(MessageHandler5) {
  message_received = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  CHECK(!message_received);
  isolate->AddMessageListener(check_message_5a);
  LocalContext context;
  v8::ScriptOrigin origin1 = v8::ScriptOrigin(v8_str("6.75"), 1, 2, true);
  v8::Local<v8::Script> script =
      Script::Compile(context.local(), v8_str("throw 'error'"), &origin1)
          .ToLocalChecked();
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  isolate->RemoveMessageListeners(check_message_5a);

  message_received = false;
  isolate->AddMessageListener(check_message_5b);
  v8::ScriptOrigin origin2 = v8::ScriptOrigin(v8_str("6.75"), 1, 2, false);
  script = Script::Compile(context.local(), v8_str("throw 'error'"), &origin2)
               .ToLocalChecked();
  CHECK(script->Run(context.local()).IsEmpty());
  CHECK(message_received);
  // clear out the message listener
  isolate->RemoveMessageListeners(check_message_5b);
}

namespace {

// Verifies that after throwing an exception the message object is set up in
// some particular way by calling the supplied |tester| function. The tests that
// use this purposely test only a single getter as the getter updates the cached
// state of the object which could affect the results of other functions.
const char message_attributes_script[] =
    R"javascript(
    (function() {
      throw new Error();
    })();
    )javascript";

void CheckMessageAttributes(std::function<void(v8::Local<v8::Context> context,
                                               v8::Local<v8::Message> message)>
                                tester) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  TryCatch try_catch(context->GetIsolate());
  CompileRun(message_attributes_script);
  CHECK(try_catch.HasCaught());

  v8::Local<v8::Value> error = try_catch.Exception();
  v8::Local<v8::Message> message =
      v8::Exception::CreateMessage(context->GetIsolate(), error);
  CHECK(!message.IsEmpty());

  tester(context.local(), message);
}

}  // namespace

TEST(MessageGetLineNumber) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(3, message->GetLineNumber(context).FromJust());
      });
}

TEST(MessageGetStartColumn) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(12, message->GetStartColumn(context).FromJust());
      });
}

TEST(MessageGetEndColumn) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(13, message->GetEndColumn(context).FromJust());
      });
}

TEST(MessageGetStartPosition) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(31, message->GetStartPosition());
      });
}

TEST(MessageGetEndPosition) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        CHECK_EQ(32, message->GetEndPosition());
      });
}

TEST(MessageGetSource) {
  CheckMessageAttributes([](v8::Local<v8::Context> context,
                            v8::Local<v8::Message> message) {
    std::string result(*v8::String::Utf8Value(
        context->GetIsolate(), message->GetSource(context).ToLocalChecked()));
    CHECK_EQ(message_attributes_script, result);
  });
}

TEST(MessageGetSourceLine) {
  CheckMessageAttributes(
      [](v8::Local<v8::Context> context, v8::Local<v8::Message> message) {
        std::string result(*v8::String::Utf8Value(
            context->GetIsolate(),
            message->GetSourceLine(context).ToLocalChecked()));
        CHECK_EQ("      throw new Error();", result);
      });
}

TEST(GetStackTraceLimit) {
  i::v8_flags.stack_trace_limit = 10;

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  const int stack_trace_limit = isolate->GetStackTraceLimit();
  CHECK_EQ(10, stack_trace_limit);
}

TEST(GetStackTraceLimitSetFromJS) {
  i::v8_flags.stack_trace_limit = 10;

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script = v8_str("Error.stackTraceLimit = 5;\n");
  v8::Script::Compile(context.local(), script, &origin)
      .ToLocalChecked()
      ->Run(context.local())
      .ToLocalChecked();

  const int stack_trace_limit = isolate->GetStackTraceLimit();
  CHECK_EQ(5, stack_trace_limit);
}

TEST(GetStackTraceLimitSetNegativeFromJS) {
  i::v8_flags.stack_trace_limit = 10;

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script = v8_str("Error.stackTraceLimit = -5;\n");
  v8::Script::Compile(context.local(), script, &origin)
      .ToLocalChecked()
      ->Run(context.local())
      .ToLocalChecked();

  const int stack_trace_limit = isolate->GetStackTraceLimit();
  CHECK_EQ(0, stack_trace_limit);
}

void GetCurrentStackTraceID(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  v8::Local<v8::StackTrace> stack_trace =
      v8::StackTrace::CurrentStackTrace(isolate, 1);
  args.GetReturnValue().Set(v8::Integer::New(isolate, stack_trace->GetID()));
}

THREADED_TEST(CurrentStackTraceHasUniqueIDs) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "getCurrentStackTraceID",
             v8::FunctionTemplate::New(isolate, GetCurrentStackTraceID));
  LocalContext context(nullptr, templ);
  CompileRun(
      "function foo() {"
      "  return getCurrentStackTraceID();"
      "}");
  Local<Function> foo = Local<Function>::Cast(
      context->Global()->Get(context.local(), v8_str("foo")).ToLocalChecked());

  Local<v8::Integer> id1 =
      foo->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
          .ToLocalChecked()
          .As<v8::Integer>();
  Local<v8::Integer> id2 =
      foo->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
          .ToLocalChecked()
          .As<v8::Integer>();

  CHECK_NE(id1->Value(), id2->Value());
}

void GetCurrentStackTrace(const v8::FunctionCallbackInfo<v8::Value>& args) {
  std::stringstream ss;
  v8::Message::PrintCurrentStackTrace(args.GetIsolate(), ss);
  std::string str = ss.str();
  args.GetReturnValue().Set(v8_str(str.c_str()));
}

THREADED_TEST(MessagePrintCurrentStackTrace) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "getCurrentStackTrace",
             v8::FunctionTemplate::New(isolate, GetCurrentStackTrace));
  LocalContext context(nullptr, templ);

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script = v8_str(
      "function c() {\n"
      "  return getCurrentStackTrace();\n"
      "}\n"
      "function b() {\n"
      "  return c();\n"
      "}\n"
      "function a() {\n"
      "  return b();\n"
      "}\n"
      "a();");
  v8::Local<v8::Value> stack_trace =
      v8::Script::Compile(context.local(), script, &origin)
          .ToLocalChecked()
          ->Run(context.local())
          .ToLocalChecked();

  CHECK(stack_trace->IsString());
  v8::String::Utf8Value stack_trace_value(isolate,
                                          stack_trace.As<v8::String>());
  std::string stack_trace_string(*stack_trace_value);
  std::string expected(
      "c (test:2:10)\n"
      "b (test:5:10)\n"
      "a (test:8:10)\n"
      "test:10:1");
  CHECK_EQ(stack_trace_string, expected);
}

THREADED_TEST(GetSetProperty) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("foo"), v8_num(14))
            .FromJust());
  CHECK(context->Global()
            ->Set(context.local(), v8_str("12"), v8_num(92))
            .FromJust());
  CHECK(context->Global()
            ->Set(context.local(), v8::Integer::New(isolate, 16), v8_num(32))
            .FromJust());
  CHECK(context->Global()
            ->Set(context.local(), v8_num(13), v8_num(56))
            .FromJust());
  Local<Value> foo = CompileRun("this.foo");
  CHECK_EQ(14, foo->Int32Value(context.local()).FromJust());
  Local<Value> twelve = CompileRun("this[12]");
  CHECK_EQ(92, twelve->Int32Value(context.local()).FromJust());
  Local<Value> sixteen = CompileRun("this[16]");
  CHECK_EQ(32, sixteen->Int32Value(context.local()).FromJust());
  Local<Value> thirteen = CompileRun("this[13]");
  CHECK_EQ(56, thirteen->Int32Value(context.local()).FromJust());
  CHECK_EQ(92, context->Global()
                   ->Get(context.local(), v8::Integer::New(isolate, 12))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(92, context->Global()
                   ->Get(context.local(), v8_str("12"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(92, context->Global()
                   ->Get(context.local(), v8_num(12))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(32, context->Global()
                   ->Get(context.local(), v8::Integer::New(isolate, 16))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(32, context->Global()
                   ->Get(context.local(), v8_str("16"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(32, context->Global()
                   ->Get(context.local(), v8_num(16))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(56, context->Global()
                   ->Get(context.local(), v8::Integer::New(isolate, 13))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(56, context->Global()
                   ->Get(context.local(), v8_str("13"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(56, context->Global()
                   ->Get(context.local(), v8_num(13))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
}


THREADED_TEST(PropertyAttributes) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  // none
  Local<String> prop = v8_str("none");
  CHECK(context->Global()->Set(context.local(), prop, v8_num(7)).FromJust());
  CHECK_EQ(v8::None, context->Global()
                         ->GetPropertyAttributes(context.local(), prop)
                         .FromJust());
  // read-only
  prop = v8_str("read_only");
  context->Global()
      ->DefineOwnProperty(context.local(), prop, v8_num(7), v8::ReadOnly)
      .FromJust();
  CHECK_EQ(7, context->Global()
                  ->Get(context.local(), prop)
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(v8::ReadOnly, context->Global()
                             ->GetPropertyAttributes(context.local(), prop)
                             .FromJust());
  CompileRun("read_only = 9");
  CHECK_EQ(7, context->Global()
                  ->Get(context.local(), prop)
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK(context->Global()->Set(context.local(), prop, v8_num(10)).FromJust());
  CHECK_EQ(7, context->Global()
                  ->Get(context.local(), prop)
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  // dont-delete
  prop = v8_str("dont_delete");
  context->Global()
      ->DefineOwnProperty(context.local(), prop, v8_num(13), v8::DontDelete)
      .FromJust();
  CHECK_EQ(13, context->Global()
                   ->Get(context.local(), prop)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CompileRun("delete dont_delete");
  CHECK_EQ(13, context->Global()
                   ->Get(context.local(), prop)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(v8::DontDelete, context->Global()
                               ->GetPropertyAttributes(context.local(), prop)
                               .FromJust());
  // dont-enum
  prop = v8_str("dont_enum");
  context->Global()
      ->DefineOwnProperty(context.local(), prop, v8_num(28), v8::DontEnum)
      .FromJust();
  CHECK_EQ(v8::DontEnum, context->Global()
                             ->GetPropertyAttributes(context.local(), prop)
                             .FromJust());
  // absent
  prop = v8_str("absent");
  CHECK_EQ(v8::None, context->Global()
                         ->GetPropertyAttributes(context.local(), prop)
                         .FromJust());
  Local<Value> fake_prop = v8_num(1);
  CHECK_EQ(v8::None, context->Global()
                         ->GetPropertyAttributes(context.local(), fake_prop)
                         .FromJust());
  // exception
  TryCatch try_catch(context->GetIsolate());
  Local<Value> exception =
      CompileRun("({ toString: function() { throw 'exception';} })");
  CHECK(context->Global()
            ->GetPropertyAttributes(context.local(), exception)
            .IsNothing());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(context->GetIsolate(),
                                    try_catch.Exception());
  CHECK_
```