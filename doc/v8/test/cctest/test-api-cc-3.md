Response:
The user wants to understand the functionality of a V8 source code snippet located in `v8/test/cctest/test-api.cc`. I need to analyze the C++ code and explain what it does.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `test-api.cc` strongly suggests this code tests V8's C++ API. The presence of `THREADED_TEST` macros confirms this. These tests likely verify the behavior of various API functions related to object creation, property manipulation, and inheritance.

2. **Analyze individual tests:**  Go through each `THREADED_TEST` function and understand what it's testing.

    * **`DescriptorInheritance`:** This test seems to be verifying how properties are inherited through prototypes. It sets up a prototype chain with `base1` inheriting from `base` and `base2` also inheriting from `base`. It then checks if instances of `base1` and `base2` have the expected properties. The check for `obj.v2` and `obj2.v1` being undefined confirms that the inheritance is properly scoped and doesn't cross between the two independent inheritance chains.

    * **`DescriptorInheritance2`:** This test extends the inheritance concept with a deeper hierarchy (A -> B -> C -> D -> E -> F). It also introduces setting a large number of data properties on the `F` template and then checks if these properties are correctly accessible on instances of `F`. The use of `SetNativeDataProperty` indicates that native C++ getters (`GetKnurd`, `GetNirk`, `GetRino`) are involved in defining these properties.

    * **Helper functions (`SimpleAccessorGetter`, `SimpleAccessorSetter`, etc.):** These functions are clearly for setting up and testing accessors (getters and setters) for object properties. The `SymbolAccessorGetter/Setter` functions handle accessors for properties defined using `Symbol`. `ThrowingSymbolAccessorGetter` is designed to test error handling during accessor calls.

    * **`AccessorIsPreservedOnAttributeChange`:** This test specifically checks if an accessor defined on an array's `length` property remains after the property's writability is changed using `Object.defineProperty`.

    * **`UndefinedIsNotEnumerable`:**  A simple test to confirm that `undefined` is not an enumerable property.

    * **`DeepCrossLanguageRecursion`:** This test explores recursion between JavaScript and C++ functions. It sets up native C++ functions (`CallScriptRecursivelyCall`, `CallFunctionRecursivelyCall`) that call back into JavaScript, potentially creating deep call stacks. This likely tests stack management and error handling in cross-language calls.

    * **`CallbackExceptionRegression`:** This test deals with exception handling during property access within a `with` statement when interceptors are involved. It sets up an object with throwing interceptors and then tries to access and set properties within a `try...catch` block.

    * **`FunctionPrototype`:** This test verifies the functionality of setting properties on a function's `prototype`.

    * **`InternalDataFields`:** This test focuses on V8's internal data fields. It checks the setting and getting of internal fields, including handling different data types (Value, Private). The `#ifdef V8_ENABLE_CHECKS` block suggests this part specifically tests error handling when trying to cast internal fields to incorrect types.

    * **`InternalFields`:** Similar to `InternalDataFields`, this tests basic setting and getting of internal fields with a numerical value.

    * **`InternalFieldsSubclassing`:** This test delves into how internal fields are handled in class inheritance. It creates subclasses with varying numbers of in-object properties and verifies that the internal field count is correctly maintained. It seems to push the limits by using `kMaxJSApiObjectInObjectProperties`.

    * **`InternalFieldsOfRegularObjects`:** Checks that regular JavaScript objects (`Object`, object literals, `arguments`) have zero internal fields by default.

    * **`GlobalObjectInternalFields`:**  Tests setting and getting internal fields on the global object. It uses the deprecated `GetPrototype()` which is noted.

    * **`GlobalObjectHasRealIndexedProperty`:** Checks if the global object can have indexed properties.

    * **`InternalFieldsAlignedPointers`:** Tests setting and getting aligned pointers in internal fields. This is important for embedding native data within V8 objects. The test includes GC to ensure pointers are handled correctly across garbage collection cycles.

    * **`SetAlignedPointerInInternalFields`:** Tests setting multiple aligned pointers in internal fields at once.

    * **`EmbedderDataAlignedPointers`:** Similar to `InternalFieldsAlignedPointers`, but focuses on embedder data associated with the context rather than internal fields of objects.

    * **`EmbedderData`:** Tests setting and getting arbitrary data associated with the context using `SetEmbedderData` and `GetEmbedderData`.

    * **`IdentityHash`:** Tests the functionality of `GetIdentityHash()`, ensuring that the hash is consistent for the same object and different for different objects, even after garbage collection. It also explores interactions with JS accessors on the `Object.prototype`.

    * **`GlobalProxyIdentityHash`:** Specifically tests the identity hash of the global proxy object, including scenarios where it's detached and re-attached to different contexts.

    * **`SymbolIdentityHash`:** Tests the identity hash of `Symbol` objects, both those created via the C++ API and those created in JavaScript.

    * **`StringIdentityHash`:** (The snippet ends here). This test will likely verify the identity hash of string objects.

3. **Address specific constraints:**

    * **`.tq` extension:** The file has a `.cc` extension, so it's not a Torque file.
    * **JavaScript relationship:** Many tests involve running JavaScript code (`CompileRun`). I need to provide relevant JavaScript examples where applicable.
    * **Code logic inference:** For tests like `DescriptorInheritance`, I can provide hypothetical input and output based on the expected behavior.
    * **Common programming errors:**  The `InternalDataFields` test with `V8_ENABLE_CHECKS` highlights a potential error of incorrect casting of internal fields. I should explain this with an example.

4. **Summarize functionality:** Based on the analysis of individual tests, I can provide a concise summary of the file's overall purpose: testing various aspects of V8's C++ API related to object manipulation, property access, inheritance, internal fields, embedder data, and identity hashing.

5. **Structure the answer:** Organize the information logically, starting with a general overview, then detailing individual test functionalities, and finally addressing the specific constraints and providing the summary. Use clear and concise language. Use code blocks for both C++ and JavaScript examples.
这是 `v8/test/cctest/test-api.cc` 源代码的一部分，它包含了一系列用于测试 V8 C++ API 功能的单元测试。

**功能列表:**

* **测试原型继承 (Prototype Inheritance):** 涵盖了通过 `FunctionTemplate` 和 `Inherit` 方法创建原型链，并验证属性在原型链上的继承行为。
* **测试原生数据属性 (Native Data Properties):** 使用 `InstanceTemplate()->SetNativeDataProperty` 设置与原生 C++ 函数关联的数据属性，并验证其读取行为。
* **测试访问器 (Accessors):**  验证使用 `SetAccessor` 设置属性的 getter 和 setter 的行为，包括使用符号 (Symbol) 作为属性名的情况。还测试了当属性的特性（例如，可写性）发生变化时，访问器是否仍然保留。
* **测试拦截器 (Interceptors):**  测试使用 `SetHandler` 设置命名属性拦截器，并在 `with` 语句中使用时，拦截器的异常处理行为。
* **测试函数原型 (Function Prototype):** 验证在 `FunctionTemplate` 的 `PrototypeTemplate` 上设置的属性可以通过构造函数的 `prototype` 访问。
* **测试内部字段 (Internal Fields):**  验证使用 `SetInternalFieldCount` 在对象上设置内部字段，并测试其设置、获取和类型检查。这包括了对齐指针在内部字段中的存储和检索。
* **测试嵌入器数据 (Embedder Data):**  测试与 `v8::Context` 关联的嵌入器数据的设置和获取，包括对齐指针的存储和检索。
* **测试身份哈希 (Identity Hash):**  验证 `GetIdentityHash()` 方法返回的哈希值的特性，例如同一对象的哈希值不变，不同对象的哈希值不同，以及在垃圾回收后的行为。还测试了当 JavaScript 中定义了名为 `'v8::IdentityHash'` 的属性时，`GetIdentityHash()` 的行为。
* **测试全局代理对象的身份哈希 (Global Proxy Identity Hash):** 专门测试全局代理对象的身份哈希值，包括在分离和重新附加全局代理对象后的行为。
* **测试符号的身份哈希 (Symbol Identity Hash):** 验证 `Symbol` 对象的身份哈希值的特性。

**关于文件扩展名和 Torque:**

`v8/test/cctest/test-api.cc` 以 `.cc` 结尾，因此它是一个标准的 C++ 源代码文件，而不是 V8 的 Torque 源代码。Torque 文件通常以 `.tq` 结尾。

**与 JavaScript 的关系及举例:**

这个 C++ 代码直接测试了 V8 引擎提供的 C++ API，这些 API 用于在 C++ 代码中与 JavaScript 引擎进行交互。以下是一些与 JavaScript 功能相关的示例：

* **原型继承:**

```javascript
function Base(v) {
  this.v1 = v;
}

function Derived(v, w) {
  Base.call(this, v);
  this.v2 = w;
}

Derived.prototype = Object.create(Base.prototype);
Derived.prototype.constructor = Derived;

const obj = new Derived(10, 20);
console.log(obj.v1); // 输出 10 (继承自 Base)
console.log(obj.v2); // 输出 20 (Derived 自身的属性)
```

这个 JavaScript 例子演示了原型继承，这与 `DescriptorInheritance` 和 `DescriptorInheritance2` 测试所验证的 C++ API 功能相关。

* **访问器:**

```javascript
const obj = {
  _value: 0,
  get value() {
    console.log('Getting value');
    return this._value;
  },
  set value(newValue) {
    console.log('Setting value to', newValue);
    this._value = newValue;
  }
};

obj.value = 5; // 输出 'Setting value to 5'
console.log(obj.value); // 输出 'Getting value' 和 5
```

这个 JavaScript 例子展示了访问器的用法，对应于 `AccessorIsPreservedOnAttributeChange` 和其他与访问器相关的测试。

* **内部字段 (虽然 JavaScript 不能直接访问):**

V8 引擎在内部使用内部字段来存储对象的元数据和原生数据。虽然 JavaScript 代码无法直接访问这些内部字段，但 C++ API 允许设置和获取它们。这部分测试确保了这些内部机制的正确性。

**代码逻辑推理 (假设输入与输出):**

以 `DescriptorInheritance` 测试为例：

**假设输入:**

* 创建一个名为 `base` 的函数模板，并为其实例模板设置一个名为 `knurd` 的原生数据属性，getter 返回 15.2。
* 创建一个名为 `base1` 的函数模板，继承自 `base`，并为其实例模板设置一个名为 `flabby` 的原生数据属性，getter 返回 17.2，以及一个名为 `v1` 的原生数据属性，值为 10.1。
* 创建一个名为 `base2` 的函数模板，继承自 `base`，并为其实例模板设置一个名为 `v2` 的原生数据属性，值为 10.1。
* 分别基于 `base1` 和 `base2` 创建对象 `obj` 和 `obj2`。

**预期输出:**

* `CompileRun("obj.flabby()")` 应该返回 17.2。
* `CompileRun("'flabby' in obj")` 应该返回 `true`。
* `CompileRun("obj.knurd")` 应该返回 15.2。
* `CompileRun("'knurd' in obj")` 应该返回 `true`。
* `CompileRun("obj.v1")` 应该返回 10.1。
* `CompileRun("obj2.flabby()")` 应该返回 17.2。
* `CompileRun("'flabby' in obj2")` 应该返回 `true`。
* `CompileRun("obj2.knurd")` 应该返回 15.2。
* `CompileRun("'knurd' in obj2")` 应该返回 `true`。
* `CompileRun("obj2.v2")` 应该返回 10.1。
* `CompileRun("obj.v2")` 应该返回 `undefined` (因为 `v2` 是 `base2` 的属性，`obj` 是 `base1` 的实例)。
* `CompileRun("obj2.v1")` 应该返回 `undefined` (因为 `v1` 是 `base1` 的属性，`obj2` 是 `base2` 的实例)。

**用户常见的编程错误举例:**

* **错误地假设原型链上的属性是互相可见的:**  在 `DescriptorInheritance` 测试中，`obj` 是 `base1` 的实例，可以访问 `base` 和 `base1` 的属性，但不能直接访问 `base2` 的属性，反之亦然。一个常见的错误是假设在不同的原型链分支上的对象可以互相访问对方的属性。

```javascript
function A() {}
A.prototype.foo = 1;

function B() {}
B.prototype.bar = 2;

const a_instance = new A();
const b_instance = new B();

console.log(a_instance.bar); // 输出 undefined，因为 bar 在 B 的原型链上
console.log(b_instance.foo); // 输出 undefined，因为 foo 在 A 的原型链上
```

* **在 C++ API 中错误地设置或获取内部字段的类型:** `InternalDataFields` 测试中使用了 `CHECK(!field->IsValue());` 和 `#ifdef V8_ENABLE_CHECKS` 部分的代码，模拟了尝试将非 `v8::Value` 类型的内部字段强制转换为 `v8::Value` 的错误。

```c++
// 假设 obj 的内部字段 0 存储的是一个 v8::Private 对象
v8::Local<v8::Data> data = obj->GetInternalField(0);
// 错误地尝试将其转换为 v8::Value
// 这段代码在启用了 V8_ENABLE_CHECKS 的情况下会触发断言或错误处理
v8::Local<v8::Value> value = data.As<v8::Value>();
```

**功能归纳 (第 4 部分，共 36 部分):**

这部分代码主要集中在测试 V8 C++ API 中关于**对象属性 (包括原生数据属性和访问器)、原型继承、拦截器以及内部字段和嵌入器数据的基本操作和特性**。它验证了通过 C++ API 创建和操作 JavaScript 对象的关键功能，确保了这些 API 的行为符合预期，为 V8 引擎的正确运行奠定了基础。这些测试覆盖了对象模型的核心概念，是 V8 API 测试套件中的重要组成部分。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
;

  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj2"), base2->GetFunction(env.local())
                                                   .ToLocalChecked()
                                                   ->NewInstance(env.local())
                                                   .ToLocalChecked())
            .FromJust());
  CHECK_EQ(17.2,
           CompileRun("obj2.flabby()")->NumberValue(env.local()).FromJust());
  CHECK(CompileRun("'flabby' in obj2")->BooleanValue(isolate));
  CHECK_EQ(15.2, CompileRun("obj2.knurd")->NumberValue(env.local()).FromJust());
  CHECK(CompileRun("'knurd' in obj2")->BooleanValue(isolate));
  CHECK_EQ(10.1, CompileRun("obj2.v2")->NumberValue(env.local()).FromJust());

  // base1 and base2 cannot cross reference to each's prototype
  CHECK(CompileRun("obj.v2")->IsUndefined());
  CHECK(CompileRun("obj2.v1")->IsUndefined());
}

THREADED_TEST(DescriptorInheritance2) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> fun_A = v8::FunctionTemplate::New(isolate);
  fun_A->SetClassName(v8_str("A"));
  fun_A->InstanceTemplate()->SetNativeDataProperty(v8_str("knurd1"), GetKnurd);
  fun_A->InstanceTemplate()->SetNativeDataProperty(v8_str("nirk1"), GetNirk);
  fun_A->InstanceTemplate()->SetNativeDataProperty(v8_str("rino1"), GetRino);

  v8::Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  fun_B->SetClassName(v8_str("B"));
  fun_B->Inherit(fun_A);

  v8::Local<v8::FunctionTemplate> fun_C = v8::FunctionTemplate::New(isolate);
  fun_C->SetClassName(v8_str("C"));
  fun_C->Inherit(fun_B);
  fun_C->InstanceTemplate()->SetNativeDataProperty(v8_str("knurd2"), GetKnurd);
  fun_C->InstanceTemplate()->SetNativeDataProperty(v8_str("nirk2"), GetNirk);
  fun_C->InstanceTemplate()->SetNativeDataProperty(v8_str("rino2"), GetRino);

  v8::Local<v8::FunctionTemplate> fun_D = v8::FunctionTemplate::New(isolate);
  fun_D->SetClassName(v8_str("D"));
  fun_D->Inherit(fun_C);

  v8::Local<v8::FunctionTemplate> fun_E = v8::FunctionTemplate::New(isolate);
  fun_E->SetClassName(v8_str("E"));
  fun_E->Inherit(fun_D);
  fun_E->InstanceTemplate()->SetNativeDataProperty(v8_str("knurd3"), GetKnurd);
  fun_E->InstanceTemplate()->SetNativeDataProperty(v8_str("nirk3"), GetNirk);
  fun_E->InstanceTemplate()->SetNativeDataProperty(v8_str("rino3"), GetRino);

  v8::Local<v8::FunctionTemplate> fun_F = v8::FunctionTemplate::New(isolate);
  fun_F->SetClassName(v8_str("F"));
  fun_F->Inherit(fun_E);
  v8::Local<v8::ObjectTemplate> templ = fun_F->InstanceTemplate();
  const int kDataPropertiesNumber = 100;
  for (int i = 0; i < kDataPropertiesNumber; i++) {
    v8::Local<v8::Value> val = v8_num(i);
    v8::Local<v8::String> val_str = val->ToString(env.local()).ToLocalChecked();
    v8::Local<v8::String> name = String::Concat(isolate, v8_str("p"), val_str);

    templ->Set(name, val);
    templ->Set(val_str, val);
  }

  CHECK(env->Global()
            ->Set(env.local(), v8_str("F"),
                  fun_F->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  v8::Local<v8::Script> script = v8_compile("o = new F()");

  for (int i = 0; i < 100; i++) {
    v8::HandleScope inner_scope(isolate);
    script->Run(env.local()).ToLocalChecked();
  }
  v8::Local<v8::Object> object = script->Run(env.local())
                                     .ToLocalChecked()
                                     ->ToObject(env.local())
                                     .ToLocalChecked();

  CHECK_EQ(15.2, CompileRun("o.knurd1")->NumberValue(env.local()).FromJust());
  CHECK_EQ(15.2, CompileRun("o.knurd2")->NumberValue(env.local()).FromJust());
  CHECK_EQ(15.2, CompileRun("o.knurd3")->NumberValue(env.local()).FromJust());

  CHECK_EQ(900, CompileRun("o.nirk1")->IntegerValue(env.local()).FromJust());
  CHECK_EQ(900, CompileRun("o.nirk2")->IntegerValue(env.local()).FromJust());
  CHECK_EQ(900, CompileRun("o.nirk3")->IntegerValue(env.local()).FromJust());

  CHECK_EQ(560, CompileRun("o.rino1")->IntegerValue(env.local()).FromJust());
  CHECK_EQ(560, CompileRun("o.rino2")->IntegerValue(env.local()).FromJust());
  CHECK_EQ(560, CompileRun("o.rino3")->IntegerValue(env.local()).FromJust());

  for (int i = 0; i < kDataPropertiesNumber; i++) {
    v8::Local<v8::Value> val = v8_num(i);
    v8::Local<v8::String> val_str = val->ToString(env.local()).ToLocalChecked();
    v8::Local<v8::String> name = String::Concat(isolate, v8_str("p"), val_str);

    CHECK_EQ(i, object->Get(env.local(), name)
                    .ToLocalChecked()
                    ->IntegerValue(env.local())
                    .FromJust());
    CHECK_EQ(i, object->Get(env.local(), val)
                    .ToLocalChecked()
                    ->IntegerValue(env.local())
                    .FromJust());
  }
}


// Helper functions for Interceptor/Accessor interaction tests

void SimpleAccessorGetter(Local<String> name,
                          const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Local<Object> self = info.This().As<Object>();
  info.GetReturnValue().Set(
      self->Get(info.GetIsolate()->GetCurrentContext(),
                String::Concat(info.GetIsolate(), v8_str("accessor_"), name))
          .ToLocalChecked());
}

void SimpleAccessorSetter(Local<String> name, Local<Value> value,
                          const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Local<Object> self = info.This().As<Object>();
  CHECK(self->Set(info.GetIsolate()->GetCurrentContext(),
                  String::Concat(info.GetIsolate(), v8_str("accessor_"), name),
                  value)
            .FromJust());
}

void SymbolAccessorGetter(Local<Name> name,
                          const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(name->IsSymbol());
  v8::Isolate* isolate = info.GetIsolate();
  Local<Symbol> sym = name.As<Symbol>();
  if (sym->Description(isolate)->IsUndefined()) return;
  SimpleAccessorGetter(Local<String>::Cast(sym->Description(isolate)), info);
}

void SymbolAccessorSetter(Local<Name> name, Local<Value> value,
                          const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(name->IsSymbol());
  v8::Isolate* isolate = info.GetIsolate();
  Local<Symbol> sym = name.As<Symbol>();
  if (sym->Description(isolate)->IsUndefined()) return;
  SimpleAccessorSetter(Local<String>::Cast(sym->Description(isolate)), value,
                       info);
}

void SymbolAccessorGetterReturnsDefault(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(name->IsSymbol());
  v8::Isolate* isolate = info.GetIsolate();
  Local<Symbol> sym = name.As<Symbol>();
  if (sym->Description(isolate)->IsUndefined()) return;
  info.GetReturnValue().Set(info.Data());
}

static void ThrowingSymbolAccessorGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(info.GetIsolate()->ThrowException(name));
}


THREADED_TEST(AccessorIsPreservedOnAttributeChange) {
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = CcTest::i_isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;
  v8::Local<v8::Value> res = CompileRun("var a = []; a;");
  i::Handle<i::JSReceiver> a(v8::Utils::OpenHandle(v8::Object::Cast(*res)));
  CHECK_EQ(1,
           a->map()->instance_descriptors(i_isolate)->number_of_descriptors());
  CompileRun("Object.defineProperty(a, 'length', { writable: false });");
  CHECK_EQ(0,
           a->map()->instance_descriptors(i_isolate)->number_of_descriptors());
  // But we should still have an AccessorInfo.
  i::Handle<i::String> name = i_isolate->factory()->length_string();
  i::LookupIterator it(i_isolate, a, name,
                       i::LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_EQ(i::LookupIterator::ACCESSOR, it.state());
  CHECK(IsAccessorInfo(*it.GetAccessors()));
}


THREADED_TEST(UndefinedIsNotEnumerable) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> result = CompileRun("this.propertyIsEnumerable(undefined)");
  CHECK(result->IsFalse());
}

v8::Global<Script> call_recursively_script_global;
static const int kTargetRecursionDepth = 100;  // near maximum

static void CallScriptRecursivelyCall(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = args.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  int depth = args.This()
                  ->Get(context, v8_str("depth"))
                  .ToLocalChecked()
                  ->Int32Value(context)
                  .FromJust();
  if (depth == kTargetRecursionDepth) return;
  CHECK(
      args.This()
          ->Set(context, v8_str("depth"), v8::Integer::New(isolate, depth + 1))
          .FromJust());
  args.GetReturnValue().Set(call_recursively_script_global.Get(isolate)
                                ->Run(context)
                                .ToLocalChecked());
}


static void CallFunctionRecursivelyCall(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  v8::Local<v8::Context> context = args.GetIsolate()->GetCurrentContext();
  int depth = args.This()
                  ->Get(context, v8_str("depth"))
                  .ToLocalChecked()
                  ->Int32Value(context)
                  .FromJust();
  if (depth == kTargetRecursionDepth) {
    printf("[depth = %d]\n", depth);
    return;
  }
  CHECK(args.This()
            ->Set(context, v8_str("depth"),
                  v8::Integer::New(args.GetIsolate(), depth + 1))
            .FromJust());
  v8::Local<Value> function =
      args.This()
          ->Get(context, v8_str("callFunctionRecursively"))
          .ToLocalChecked();
  args.GetReturnValue().Set(function.As<Function>()
                                ->Call(context, args.This(), 0, nullptr)
                                .ToLocalChecked());
}


THREADED_TEST(DeepCrossLanguageRecursion) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> global = ObjectTemplate::New(isolate);
  global->Set(isolate, "callScriptRecursively",
              v8::FunctionTemplate::New(isolate, CallScriptRecursivelyCall));
  global->Set(isolate, "callFunctionRecursively",
              v8::FunctionTemplate::New(isolate, CallFunctionRecursivelyCall));
  LocalContext env(nullptr, global);

  CHECK(env->Global()
            ->Set(env.local(), v8_str("depth"), v8::Integer::New(isolate, 0))
            .FromJust());
  v8::Local<Script> call_recursively_script =
      v8_compile("callScriptRecursively()");
  call_recursively_script_global.Reset(isolate, call_recursively_script);
  call_recursively_script->Run(env.local()).ToLocalChecked();
  call_recursively_script_global.Reset();

  CHECK(env->Global()
            ->Set(env.local(), v8_str("depth"), v8::Integer::New(isolate, 0))
            .FromJust());
  CompileRun("callFunctionRecursively()");
}

namespace {
v8::Intercepted ThrowingPropertyHandlerGet(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // Since this interceptor is used on "with" objects, the runtime will look up
  // @@unscopables.  Punt.
  CHECK(i::ValidateCallbackInfo(info));
  if (key->IsSymbol()) return v8::Intercepted::kNo;
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(info.GetIsolate()->ThrowException(key));
  return v8::Intercepted::kYes;
}

v8::Intercepted ThrowingPropertyHandlerSet(
    Local<Name> key, Local<Value>, const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  CHECK(!isolate->HasPendingException());
  isolate->ThrowException(key);
  CHECK(isolate->HasPendingException());
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(CallbackExceptionRegression) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(
      ThrowingPropertyHandlerGet, ThrowingPropertyHandlerSet));
  LocalContext env;
  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"),
                  obj->NewInstance(env.local()).ToLocalChecked())
            .FromJust());
  v8::Local<Value> otto =
      CompileRun("try { with (obj) { otto; } } catch (e) { e; }");
  CHECK(v8_str("otto")->Equals(env.local(), otto).FromJust());
  v8::Local<Value> netto =
      CompileRun("try { with (obj) { netto = 4; } } catch (e) { e; }");
  CHECK(v8_str("netto")->Equals(env.local(), netto).FromJust());
}


THREADED_TEST(FunctionPrototype) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> Foo = v8::FunctionTemplate::New(isolate);
  Foo->PrototypeTemplate()->Set(isolate, "plak", v8_num(321));
  LocalContext env;
  CHECK(env->Global()
            ->Set(env.local(), v8_str("Foo"),
                  Foo->GetFunction(env.local()).ToLocalChecked())
            .FromJust());
  Local<Script> script = v8_compile("Foo.prototype.plak");
  CHECK_EQ(v8_run_int32value(script), 321);
}

bool internal_field_check_called = false;
void OnInternalFieldCheck(const char* location, const char* message) {
  internal_field_check_called = true;
  exit(strcmp(location, "v8::Value::Cast") +
       strcmp(message, "Data is not a Value"));
}

// The fatal error handler would call exit() so this should not be run in
// parallel.
TEST(InternalDataFields) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = templ->InstanceTemplate();
  instance_templ->SetInternalFieldCount(1);
  Local<v8::Object> obj = templ->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK_EQ(1, obj->InternalFieldCount());
  Local<v8::Data> data = obj->GetInternalField(0);
  CHECK(data->IsValue() && data.As<v8::Value>()->IsUndefined());
  Local<v8::Private> sym = v8::Private::New(isolate, v8_str("Foo"));
  obj->SetInternalField(0, sym);
  Local<v8::Data> field = obj->GetInternalField(0);
  CHECK(!field->IsValue());
  CHECK(field->IsPrivate());
  CHECK_EQ(sym, field);

#ifdef V8_ENABLE_CHECKS
  isolate->SetFatalErrorHandler(OnInternalFieldCheck);
  USE(obj->GetInternalField(0).As<v8::Value>());
  // If it's never called this would fail.
  CHECK(internal_field_check_called);
#endif
}

THREADED_TEST(InternalFields) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = templ->InstanceTemplate();
  instance_templ->SetInternalFieldCount(1);
  Local<v8::Object> obj = templ->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK_EQ(1, obj->InternalFieldCount());
  CHECK(obj->GetInternalField(0).As<v8::Value>()->IsUndefined());
  obj->SetInternalField(0, v8_num(17));
  CHECK_EQ(17, obj->GetInternalField(0)
                   .As<v8::Value>()
                   ->Int32Value(env.local())
                   .FromJust());
}

TEST(InternalFieldsSubclassing) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  for (int nof_embedder_fields = 0;
       nof_embedder_fields < i::JSObject::kMaxJSApiObjectEmbedderFields;
       nof_embedder_fields++) {
    Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
    Local<v8::ObjectTemplate> instance_templ = templ->InstanceTemplate();
    instance_templ->SetInternalFieldCount(nof_embedder_fields);
    Local<Function> constructor =
        templ->GetFunction(env.local()).ToLocalChecked();
    // Check that instances have the correct NOF properties.
    Local<v8::Object> obj =
        constructor->NewInstance(env.local()).ToLocalChecked();

    i::DirectHandle<i::JSObject> i_obj =
        i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*obj));
    CHECK_EQ(nof_embedder_fields, obj->InternalFieldCount());
    CHECK_EQ(0, i_obj->map()->GetInObjectProperties());
    // Check writing and reading internal fields.
    for (int j = 0; j < nof_embedder_fields; j++) {
      CHECK(obj->GetInternalField(j).As<v8::Value>()->IsUndefined());
      int value = 17 + j;
      obj->SetInternalField(j, v8_num(value));
    }
    for (int j = 0; j < nof_embedder_fields; j++) {
      int value = 17 + j;
      CHECK_EQ(value, obj->GetInternalField(j)
                          .As<v8::Value>()
                          ->Int32Value(env.local())
                          .FromJust());
    }
    CHECK(env->Global()
              ->Set(env.local(), v8_str("BaseClass"), constructor)
              .FromJust());
    // Create various levels of subclasses to stress instance size calculation.
    const int kMaxNofProperties =
        i::JSObject::kMaxJSApiObjectInObjectProperties -
        nof_embedder_fields * i::kEmbedderDataSlotSizeInTaggedSlots;
    // Select only a few values to speed up the test.
    int sizes[] = {0,
                   1,
                   2,
                   3,
                   4,
                   5,
                   6,
                   kMaxNofProperties / 4,
                   kMaxNofProperties / 2,
                   kMaxNofProperties - 2,
                   kMaxNofProperties - 1,
                   kMaxNofProperties + 1,
                   kMaxNofProperties + 2,
                   kMaxNofProperties * 2,
                   kMaxNofProperties * 2};
    for (size_t i = 0; i < arraysize(sizes); i++) {
      int nof_properties = sizes[i];
      bool in_object_only = nof_properties <= kMaxNofProperties;
      std::ostringstream src;
      // Assembler source string for a subclass with {nof_properties}
      // in-object properties.
      src << "(function() {\n"
          << "  class SubClass extends BaseClass {\n"
          << "    constructor() {\n"
          << "      super();\n";
      // Set {nof_properties} instance properties in the constructor.
      for (int j = 0; j < nof_properties; j++) {
        src << "      this.property" << j << " = " << j << ";\n";
      }
      src << "    }\n"
          << "  };\n"
          << "  let instance;\n"
          << "  for (let i = 0; i < 3; i++) {\n"
          << "    instance = new SubClass();\n"
          << "  }"
          << "  return instance;\n"
          << "})();";
      Local<v8::Object> value = CompileRun(src.str().c_str()).As<v8::Object>();

      i::DirectHandle<i::JSObject> i_value =
          i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*value));
#ifdef VERIFY_HEAP
      i_value->HeapObjectVerify(i_isolate);
      i_value->map()->HeapObjectVerify(i_isolate);
      i_value->map()->FindRootMap(i_isolate)->HeapObjectVerify(i_isolate);
#endif
      CHECK_EQ(nof_embedder_fields, value->InternalFieldCount());
      if (in_object_only) {
        CHECK_LE(nof_properties, i_value->map()->GetInObjectProperties());
      } else {
        CHECK_LE(i_value->map()->GetInObjectProperties(), kMaxNofProperties);
      }

      // Make sure we get the precise property count.
      i::MapUpdater::CompleteInobjectSlackTracking(
          i_isolate, i_value->map()->FindRootMap(i_isolate));
      // TODO(cbruni): fix accounting to make this condition true.
      // CHECK_EQ(0, i_value->map()->UnusedPropertyFields());
      if (in_object_only) {
        CHECK_EQ(nof_properties, i_value->map()->GetInObjectProperties());
      } else {
        CHECK_LE(i_value->map()->GetInObjectProperties(), kMaxNofProperties);
      }
    }
  }
}

THREADED_TEST(InternalFieldsOfRegularObjects) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  const char* sources[] = {"new Object()", "{ a: 'a property' }", "arguments"};
  for (size_t i = 0; i < arraysize(sources); ++i) {
    v8::base::ScopedVector<char> source(128);
    v8::base::SNPrintF(source, "(function() { return %s })()", sources[i]);
    v8::Local<v8::Object> obj = CompileRun(source.begin()).As<v8::Object>();
    CHECK_EQ(0, obj->InternalFieldCount());
  }
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

THREADED_TEST(GlobalObjectInternalFields) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::ObjectTemplate> global_template = v8::ObjectTemplate::New(isolate);
  global_template->SetInternalFieldCount(1);
  LocalContext env(nullptr, global_template);
  v8::Local<v8::Object> global_proxy = env->Global();
  v8::Local<v8::Object> global = global_proxy->GetPrototype().As<v8::Object>();
  CHECK_EQ(1, global->InternalFieldCount());
  CHECK(global->GetInternalField(0).As<v8::Value>()->IsUndefined());
  global->SetInternalField(0, v8_num(17));
  CHECK_EQ(17, global->GetInternalField(0)
                   .As<v8::Value>()
                   ->Int32Value(env.local())
                   .FromJust());
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

THREADED_TEST(GlobalObjectHasRealIndexedProperty) {
  LocalContext env;
  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::Object> global = env->Global();
  CHECK(global->Set(env.local(), 0, v8_str("value")).FromJust());
  CHECK(global->HasRealIndexedProperty(env.local(), 0).FromJust());
}

static void CheckAlignedPointerInInternalField(Local<v8::Object> obj,
                                               void* value) {
  CHECK(HAS_SMI_TAG(reinterpret_cast<i::Address>(value)));
  obj->SetAlignedPointerInInternalField(0, value);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(value, obj->GetAlignedPointerFromInternalField(0));
  CHECK_EQ(value,
           obj->GetAlignedPointerFromInternalField(CcTest::isolate(), 0));
}

THREADED_TEST(InternalFieldsAlignedPointers) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = templ->InstanceTemplate();
  instance_templ->SetInternalFieldCount(1);
  Local<v8::Object> obj = templ->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK_EQ(1, obj->InternalFieldCount());

  CheckAlignedPointerInInternalField(obj, nullptr);

  int* heap_allocated = new int[100];
  CheckAlignedPointerInInternalField(obj, heap_allocated);
  delete[] heap_allocated;

  int stack_allocated[100];
  CheckAlignedPointerInInternalField(obj, stack_allocated);

  // The aligned pointer must have the top bits be zero on 64-bit machines (at
  // least if the sandboxed external pointers are enabled).
  void* huge = reinterpret_cast<void*>(0x0000fffffffffffe);
  CheckAlignedPointerInInternalField(obj, huge);

  v8::Global<v8::Object> persistent(isolate, obj);
  CHECK_EQ(1, Object::InternalFieldCount(persistent));
  CHECK_EQ(huge, Object::GetAlignedPointerFromInternalField(persistent, 0));
}

THREADED_TEST(SetAlignedPointerInInternalFields) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = templ->InstanceTemplate();
  instance_templ->SetInternalFieldCount(2);
  Local<v8::Object> obj = templ->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK_EQ(2, obj->InternalFieldCount());

  int* heap_allocated_1 = new int[100];
  int* heap_allocated_2 = new int[100];
  int indices[] = {0, 1};
  void* values[] = {heap_allocated_1, heap_allocated_2};

  obj->SetAlignedPointerInInternalFields(2, indices, values);
  i::heap::InvokeMajorGC(CcTest::heap());
  {
    v8::SealHandleScope no_handle_leak(isolate);
    CHECK_EQ(heap_allocated_1, obj->GetAlignedPointerFromInternalField(0));
    CHECK_EQ(heap_allocated_2, obj->GetAlignedPointerFromInternalField(1));

    CHECK_EQ(heap_allocated_1,
             obj->GetAlignedPointerFromInternalField(isolate, 0));
    CHECK_EQ(heap_allocated_2,
             obj->GetAlignedPointerFromInternalField(isolate, 1));
  }

  indices[0] = 1;
  indices[1] = 0;
  obj->SetAlignedPointerInInternalFields(2, indices, values);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(heap_allocated_2, obj->GetAlignedPointerFromInternalField(0));
  CHECK_EQ(heap_allocated_1, obj->GetAlignedPointerFromInternalField(1));

  CHECK_EQ(heap_allocated_2,
           obj->GetAlignedPointerFromInternalField(isolate, 0));
  CHECK_EQ(heap_allocated_1,
           obj->GetAlignedPointerFromInternalField(isolate, 1));

  delete[] heap_allocated_1;
  delete[] heap_allocated_2;
}

static void CheckAlignedPointerInEmbedderData(LocalContext* env,
                                              v8::Local<v8::Object> some_obj,
                                              int index, void* value) {
  CHECK_EQ(0, static_cast<int>(reinterpret_cast<uintptr_t>(value) & 0x1));
  (*env)->SetAlignedPointerInEmbedderData(index, value);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(value, (*env)->GetAlignedPointerFromEmbedderData(index));
  CHECK_EQ(value,
           some_obj->GetAlignedPointerFromEmbedderDataInCreationContext(index));
  CHECK_EQ(value, some_obj->GetAlignedPointerFromEmbedderDataInCreationContext(
                      CcTest::isolate(), index));
}

static void* AlignedTestPointer(int i) {
  return reinterpret_cast<void*>(i * 1234);
}


THREADED_TEST(EmbedderDataAlignedPointers) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> obj = v8::Object::New(isolate);

  CheckAlignedPointerInEmbedderData(&env, obj, 0, nullptr);
  CHECK_EQ(1, (*env)->GetNumberOfEmbedderDataFields());

  int* heap_allocated = new int[100];
  CheckAlignedPointerInEmbedderData(&env, obj, 1, heap_allocated);
  CHECK_EQ(2, (*env)->GetNumberOfEmbedderDataFields());
  delete[] heap_allocated;

  int stack_allocated[100];
  CheckAlignedPointerInEmbedderData(&env, obj, 2, stack_allocated);
  CHECK_EQ(3, (*env)->GetNumberOfEmbedderDataFields());

  // The aligned pointer must have the top bits be zero on 64-bit machines (at
  // least if the sandboxed external pointers are enabled).
  void* huge = reinterpret_cast<void*>(0x0000fffffffffffe);
  CheckAlignedPointerInEmbedderData(&env, obj, 3, huge);
  CHECK_EQ(4, (*env)->GetNumberOfEmbedderDataFields());

  // Test growing of the embedder data's backing store.
  for (int i = 0; i < 100; i++) {
    env->SetAlignedPointerInEmbedderData(i, AlignedTestPointer(i));
  }
  i::heap::InvokeMajorGC(CcTest::heap());
  for (int i = 0; i < 100; i++) {
    v8::SealHandleScope no_handle_leak(env->GetIsolate());
    CHECK_EQ(AlignedTestPointer(i), env->GetAlignedPointerFromEmbedderData(i));
  }
}

static void CheckEmbedderData(LocalContext* env, int index,
                              v8::Local<Value> data) {
  (*env)->SetEmbedderData(index, data);
  CHECK((*env)->GetEmbedderData(index)->StrictEquals(data));
}


THREADED_TEST(EmbedderData) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  CHECK_EQ(0, (*env)->GetNumberOfEmbedderDataFields());
  CheckEmbedderData(&env, 3, v8_str("The quick brown fox jumps"));
  CHECK_EQ(4, (*env)->GetNumberOfEmbedderDataFields());
  CheckEmbedderData(&env, 2, v8_str("over the lazy dog."));
  CHECK_EQ(4, (*env)->GetNumberOfEmbedderDataFields());
  CheckEmbedderData(&env, 1, v8::Number::New(isolate, 1.2345));
  CHECK_EQ(4, (*env)->GetNumberOfEmbedderDataFields());
  CheckEmbedderData(&env, 0, v8::Boolean::New(isolate, true));
  CHECK_EQ(4, (*env)->GetNumberOfEmbedderDataFields());
  CheckEmbedderData(&env, 211, v8::Boolean::New(isolate, true));
  CHECK_EQ(212, (*env)->GetNumberOfEmbedderDataFields());
}


THREADED_TEST(IdentityHash) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Ensure that the test starts with an fresh heap to test whether the hash
  // code is based on the address.
  i::heap::InvokeMajorGC(CcTest::heap());
  Local<v8::Object> obj = v8::Object::New(isolate);
  int hash = obj->GetIdentityHash();
  int hash1 = obj->GetIdentityHash();
  CHECK_EQ(hash, hash1);
  int hash2 = v8::Object::New(isolate)->GetIdentityHash();
  // Since the identity hash is essentially a random number two consecutive
  // objects should not be assigned the same hash code. If the test below fails
  // the random number generator should be evaluated.
  CHECK_NE(hash, hash2);
  i::heap::InvokeMajorGC(CcTest::heap());
  int hash3 = v8::Object::New(isolate)->GetIdentityHash();
  // Make sure that the identity hash is not based on the initial address of
  // the object alone. If the test below fails the random number generator
  // should be evaluated.
  CHECK_NE(hash, hash3);
  int hash4 = obj->GetIdentityHash();
  CHECK_EQ(hash, hash4);

  // Check identity hashes behaviour in the presence of JS accessors.
  // Put a getter for 'v8::IdentityHash' on the Object's prototype:
  {
    CompileRun("Object.prototype['v8::IdentityHash'] = 42;\n");
    Local<v8::Object> o1 = v8::Object::New(isolate);
    Local<v8::Object> o2 = v8::Object::New(isolate);
    CHECK_NE(o1->GetIdentityHash(), o2->GetIdentityHash());
  }
  {
    CompileRun(
        "function cnst() { return 42; };\n"
        "Object.prototype.__defineGetter__('v8::IdentityHash', cnst);\n");
    Local<v8::Object> o1 = v8::Object::New(isolate);
    Local<v8::Object> o2 = v8::Object::New(isolate);
    CHECK_NE(o1->GetIdentityHash(), o2->GetIdentityHash());
  }
}


void GlobalProxyIdentityHash(bool set_in_js) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  Local<Object> global_proxy = env->Global();
  i::DirectHandle<i::Object> i_global_proxy =
      v8::Utils::OpenDirectHandle(*global_proxy);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("global"), global_proxy)
            .FromJust());
  int32_t hash1;
  if (set_in_js) {
    CompileRun("var m = new Set(); m.add(global);");
    i::Tagged<i::Object> original_hash = i::Object::GetHash(*i_global_proxy);
    CHECK(IsSmi(original_hash));
    hash1 = i::Smi::ToInt(original_hash);
  } else {
    hash1 = i::Object::GetOrCreateHash(*i_global_proxy, i_isolate).value();
  }
  // Hash should be retained after being detached.
  env->DetachGlobal();
  int hash2 = global_proxy->GetIdentityHash();
  CHECK_EQ(hash1, hash2);
  {
    // Re-attach global proxy to a new context, hash should stay the same.
    LocalContext env2(nullptr, Local<ObjectTemplate>(), global_proxy);
    int hash3 = global_proxy->GetIdentityHash();
    CHECK_EQ(hash1, hash3);
  }
}


THREADED_TEST(GlobalProxyIdentityHash) {
  GlobalProxyIdentityHash(true);
  GlobalProxyIdentityHash(false);
}


TEST(SymbolIdentityHash) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  {
    Local<v8::Symbol> symbol = v8::Symbol::New(isolate);
    int hash = symbol->GetIdentityHash();
    int hash1 = symbol->GetIdentityHash();
    CHECK_EQ(hash, hash1);
    i::heap::InvokeMajorGC(CcTest::heap());
    int hash3 = symbol->GetIdentityHash();
    CHECK_EQ(hash, hash3);
  }

  {
    v8::Local<v8::Symbol> js_symbol =
        CompileRun("Symbol('foo')").As<v8::Symbol>();
    int hash = js_symbol->GetIdentityHash();
    int hash1 = js_symbol->GetIdentityHash();
    CHECK_EQ(hash, hash1);
    i::heap::InvokeMajorGC(CcTest::heap());
    int hash3 = js_symbol->GetIdentityHash();
    CHECK_EQ(hash, hash3);
  }
}


TEST(StringIdentityHash) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::H
```