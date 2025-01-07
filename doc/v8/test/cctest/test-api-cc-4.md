Response:
The user wants a summary of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite. I need to identify the functionalities being tested in this code.

The code uses the V8 API to test various aspects of object properties, including:

1. **String Identity Hash:**  Verifying that `GetIdentityHash` returns the same value for identical strings, even after garbage collection.
2. **Symbols:** Testing the creation, comparison, description, and usage of `v8::Symbol` as object properties. This includes setting and getting symbol properties, checking for their existence, and deleting them. It also covers symbol properties in the prototype chain.
3. **Symbol Template Properties:** Checking if symbols can be used as property names in template prototypes.
4. **Private Properties on Proxies:** Testing the functionality of `v8::Private` for setting, getting, deleting, and checking the existence of private properties on `v8::Proxy` objects.
5. **Private Properties:** Similar to the proxy test, but for regular `v8::Object` instances.
6. **Global Symbols:** Testing the creation and retrieval of global symbols using `v8::Symbol::For` and `v8::Symbol::ForApi`, and comparing them with symbols created via JavaScript.
7. **Global Symbols without Context:** Testing `v8::Symbol::For` and `v8::Symbol::ForApi` when no explicit context is active.
8. **Well-Known Symbols:** Verifying that the V8 API provides access to well-known symbols like `Symbol.iterator`, and that these match the symbols accessible in JavaScript.
9. **Global Privates:** Testing the creation and access of global private symbols using `v8::Private::ForApi`.
10. **Hidden Properties:**  Testing the behavior of private properties as "hidden" properties, ensuring they are not enumerable or accessible via regular property access methods.
11. **Regress97784:** A regression test specifically for a bug related to interactions between `Object.prototype` and hidden properties.
12. **External:** Testing the creation and usage of `v8::External` objects to wrap raw C++ pointers and pass them to JavaScript.
13. **Global Handle:** Testing the creation, persistence, and resetting of `v8::Persistent` handles for V8 objects.
14. **Resetting Global Handle:** Specifically testing the behavior of resetting a `v8::Persistent` handle to a different value or an empty value.
15. **Global:** Testing the `v8::Global` smart pointer, which manages the lifecycle of V8 objects and its interaction with `v8::Persistent`.
16. **Weak Callbacks:** Testing the mechanism for setting weak callbacks on V8 objects, which get triggered when the object is garbage collected.

Based on this analysis, I can now generate the summary. The code snippet is focused on testing various object property features in V8, including symbols, private properties, and the interaction between C++ and JavaScript via the V8 API.
这是 V8 源代码 `v8/test/cctest/test-api.cc` 的第 5 部分，主要涵盖了以下功能：

**1. 字符串的 Identity Hash：**

*   **功能:** 测试 `v8::String` 对象的 `GetIdentityHash()` 方法。该方法用于获取字符串的唯一哈希值，即使在垃圾回收后，相同内容的字符串的哈希值也应该保持不变。
*   **代码逻辑推理:**
    *   假设输入一个字符串 "str1"。
    *   第一次调用 `GetIdentityHash()` 得到一个哈希值 `hash`。
    *   第二次调用 `GetIdentityHash()` 应该得到相同的哈希值 `hash`。
    *   进行一次 Major GC。
    *   第三次调用 `GetIdentityHash()` 仍然应该得到相同的哈希值 `hash`。
    *   创建另一个内容相同的字符串 "str1"。
    *   调用其 `GetIdentityHash()` 应该得到与之前相同的哈希值 `hash`。

**2. Symbol 属性：**

*   **功能:**  测试 `v8::Symbol` 的创建、比较、描述以及作为对象属性的用法。包括：
    *   创建无描述和有描述的 Symbol。
    *   检查 Symbol 的类型和是否相等 (`Equals`, `StrictEquals`)。
    *   获取 Symbol 的描述。
    *   Symbol 可以作为对象的属性名进行设置、获取、判断是否存在和删除。
    *   测试 Symbol 属性的特性（默认不可枚举）。
    *   测试通过 `SetNativeDataProperty` 设置带有 getter/setter 的 Symbol 属性。
    *   测试 Symbol 属性的继承性。

*   **与 Javascript 的关系和举例:**

    ```javascript
    const sym1 = Symbol();
    const sym2 = Symbol("my-symbol");
    const obj = {};

    console.log(typeof sym1); // "symbol"
    console.log(typeof sym2); // "symbol"

    console.log(sym1 === sym1); // true
    console.log(sym2 === sym2); // true
    console.log(sym1 === sym2); // false

    console.log(sym2.description); // "my-symbol"

    obj[sym1] = 1503;
    console.log(obj[sym1]); // 1503
    console.log(sym1 in obj); // true
    delete obj[sym1];
    console.log(sym1 in obj); // false

    Object.defineProperty(obj, Symbol('accessor'), {
      get() { return this._accessor; },
      set(value) { this._accessor = value; }
    });

    obj[Symbol('accessor')] = 42;
    console.log(obj[Symbol('accessor')]); // 42 (注意：每次 Symbol() 都是新的)
    ```

**3. Symbol 模板属性：**

*   **功能:** 测试在 `v8::FunctionTemplate` 的原型模板中使用 Symbol 作为属性名。

*   **与 Javascript 的关系和举例:**

    ```javascript
    const sym = Symbol();
    function Foo() {}
    Foo.prototype[sym] = function() { console.log('symbol method'); };

    const fooInstance = new Foo();
    fooInstance[sym](); // "symbol method"
    ```

**4. Proxy 上的 Private 属性：**

*   **功能:** 测试在 `v8::Proxy` 对象上使用 `v8::Private` 创建、设置、获取、删除私有属性。

*   **与 Javascript 的关系和举例:**  虽然 JavaScript 本身没有直接的 "private 属性" 概念，但 V8 的 `v8::Private`  是为了在 C++ 层面模拟和控制这种行为，可能用于实现某些语言特性或 API。在用户层面，可以使用 WeakMap 或闭包来模拟私有性。

**5. Private 属性：**

*   **功能:** 测试在普通 `v8::Object` 对象上使用 `v8::Private` 创建、设置、获取、删除私有属性。

*   **与 Javascript 的关系和举例:**  同上，`v8::Private` 是 C++ 层的概念，JavaScript 中模拟私有性通常使用 WeakMap 或闭包。

**6. 全局 Symbol：**

*   **功能:** 测试使用 `v8::Symbol::For` 和 `v8::Symbol::ForApi` 创建全局 Symbol，以及与 JavaScript 中 `Symbol.for()` 创建的全局 Symbol 的关联。

*   **与 Javascript 的关系和举例:**

    ```javascript
    const globalSym1 = Symbol.for('my-symbol');
    const globalSym2 = Symbol.for('my-symbol');
    console.log(globalSym1 === globalSym2); // true

    const sym = Symbol('my-symbol');
    console.log(globalSym1 === sym); // false
    ```

**7. 无 Context 的全局 Symbol：**

*   **功能:** 测试在没有显式 Context 的情况下，`v8::Symbol::For` 和 `v8::Symbol::ForApi` 的工作情况。

**8. Well-Known Symbol：**

*   **功能:** 测试 V8 API 是否能正确获取预定义的 Well-Known Symbols (例如 `Symbol.iterator`, `Symbol.asyncIterator` 等)。

*   **与 Javascript 的关系和举例:**

    ```javascript
    console.log(Symbol.iterator); // Symbol(Symbol.iterator)
    const arr = [1, 2, 3];
    const iterator = arr[Symbol.iterator]();
    console.log(iterator.next()); // { value: 1, done: false }
    ```

**9. 全局 Private 属性：**

*   **功能:** 测试使用 `v8::Private::ForApi` 创建全局 Private 属性。

**10. Hidden 属性：**

*   **功能:** 测试使用 `v8::Private` 创建的属性是否是 "隐藏" 的，即无法通过常规的对象属性访问方法 (`Has`, `Get`) 访问到。

*   **与 Javascript 的关系和举例:**  `v8::Private` 在 C++ 层面提供了类似隐藏属性的功能，JavaScript 中没有直接对应的概念。

**11. Regress97784：**

*   **功能:**  这是一个回归测试，用于验证修复了 crbug.com/97784 上的一个 bug。该 bug 与修改 `Object.prototype` 如何影响隐藏属性有关。

*   **用户常见的编程错误:**  在 JavaScript 中，直接修改 `Object.prototype` 是一个潜在的危险操作，因为它会影响到所有继承自 `Object.prototype` 的对象。这可能导致意外的行为和难以追踪的错误。例如：

    ```javascript
    Object.prototype.myHiddenProp = 42; // 错误的做法！

    const obj = {};
    console.log(obj.myHiddenProp); // 42 (即使 obj 本身没有定义这个属性)
    ```

**12. External：**

*   **功能:** 测试 `v8::External` 对象的创建和使用。`v8::External` 用于在 V8 中包装 C++ 的原始指针，使得 JavaScript 可以持有这些指针。

*   **与 Javascript 的关系和举例:**  虽然 JavaScript 不能直接操作原始指针，但 V8 允许通过 `v8::External` 将 C++ 数据传递给 JavaScript 环境。这在实现 Native 模块时非常有用。

    ```c++
    int myInt = 10;
    Local<External> external = External::New(isolate, &myInt);

    // 在 JavaScript 中获取并使用
    // (需要通过 Native 模块的方式将 external 传递到 JS)
    ```

**13. GlobalHandle：**

*   **功能:** 测试 `v8::Persistent` 句柄的创建、重置和使用。`v8::Persistent` 用于在超出 `v8::HandleScope` 的生命周期后仍然持有 V8 对象。

**14. ResettingGlobalHandle：**

*   **功能:**  专门测试重置 `v8::Persistent` 句柄的行为，包括重置为不同的值或空值。

**15. Global：**

*   **功能:** 测试 `v8::Global` 智能指针的使用。`v8::Global` 是 `v8::Persistent` 的 RAII 包装器，可以更方便地管理全局句柄的生命周期。

**16. Weak Callbacks：**

*   **功能:** 测试弱回调机制。当一个带有弱回调的对象即将被垃圾回收时，会触发注册的回调函数。这里测试了两阶段的弱回调。

**归纳一下第 5 部分的功能：**

这部分 `test-api.cc` 主要集中测试 V8 API 中关于 **对象属性** 的各种特性，包括：

*   **字符串的哈希值:** 验证字符串的唯一标识。
*   **Symbol 属性:**  深入测试 Symbol 作为对象属性的各种行为，包括创建、比较、访问、继承等。
*   **Private 属性:** 测试 V8 提供的私有属性机制，包括在普通对象和 Proxy 对象上的使用。
*   **Global Symbol 和 Private 属性:** 测试全局 Symbol 和 Private 属性的创建和访问方式。
*   **Well-Known Symbol:** 验证对预定义 Symbol 的访问。
*   **隐藏属性:**  确认 Private 属性的隐藏特性。
*   **C++ 和 JavaScript 的交互:** 通过 `v8::External` 测试 C++ 数据向 JavaScript 的传递。
*   **对象生命周期管理:**  测试 `v8::Persistent` 和 `v8::Global` 这两种管理 V8 对象生命周期的方式，以及弱回调机制。

总而言之，这部分代码是对 V8 API 中核心的对象模型和属性管理功能进行细致的测试。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共36部分，请归纳一下它的功能

"""
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


void S
"""


```