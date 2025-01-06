Response: The user wants a summary of the C++ code provided in the file `v8/test/cctest/test-api.cc`. This is part 2 of 18 parts. The code seems to be testing various aspects of the V8 C++ API, particularly focusing on how C++ objects and values interact with Javascript.

My plan is to go through each `TEST` and `THREADED_TEST` block and summarise its purpose. Then I'll identify any connections to Javascript and provide Javascript examples.

Here's a breakdown of the tests in this part:

1. **`IntegerValueTooBigForInt32`**: Checks handling of unsigned integers larger than `INT32_MAX` when converted to `v8::Integer`.
2. **`IsNativeError`**: Verifies the `IsNativeError` method for Javascript error objects.
3. **`IsGeneratorFunctionOrObject`**: Tests the `IsGeneratorFunction` and `IsGeneratorObject` methods.
4. **`IsAsyncFunction`**: Tests the `IsAsyncFunction` method.
5. **`ArgumentsObject`**: Checks the `IsArgumentsObject` method.
6. **`IsMapOrSet`**: Tests the `IsMap`, `IsSet`, `IsWeakMap`, and `IsWeakSet` methods.
7. **`StringObject`**: Tests the `IsStringObject` method and the creation/manipulation of `v8::StringObject`.
8. **`StringObjectDelete`**: Checks if deleting properties on a `String` object works as expected.
9. **`NumberObject`**: Tests the `IsNumberObject` method and creation/manipulation of `v8::NumberObject`.
10. **`BigIntObject`**: Tests the `IsBigIntObject` and `IsBigInt` methods and interaction with `v8::BigIntObject`.
11. **`BooleanObject`**: Tests the `IsBooleanObject` method and creation/manipulation of `v8::BooleanObject`.
12. **`PrimitiveAndWrappedBooleans`**: Compares primitive booleans (`v8::Boolean`) and wrapped boolean objects (`v8::BooleanObject`).
13. **`Number`**: Tests the creation of `v8::Number` objects.
14. **`ToNumber`**: Checks the `NumberValue` method for converting Javascript values to numbers.
15. **`Date`**: Tests the creation and manipulation of `v8::Date` objects.
16. **`Boolean`**: Tests the `BooleanValue` method for converting various Javascript values to booleans.

Now, I will proceed with generating the summary and Javascript examples.
这个C++源代码文件 (`v8/test/cctest/test-api.cc`) 的第2部分主要测试了 V8 C++ API 中关于 **值类型检查** 和 **基本类型对象** 的功能。它验证了各种 `Is...` 方法的正确性，以及如何创建和操作与 Javascript 基本类型相对应的 C++ 对象。

以下是该部分功能的归纳：

*   **整数处理**: 测试了如何创建和检查超出 `int32` 范围的无符号整数的 `v8::Integer` 对象。
*   **原生错误对象**: 验证了如何判断一个 Javascript 对象是否为原生错误对象 (例如 `SyntaxError`)。
*   **生成器函数和对象**: 测试了如何区分 Javascript 的生成器函数和生成器对象。
*   **异步函数**: 验证了如何判断一个 Javascript 函数是否为异步函数。
*   **arguments 对象**: 测试了如何判断一个 Javascript 对象是否为 `arguments` 对象。
*   **Map 和 Set 对象**: 验证了如何判断一个 Javascript 对象是否为 `Map`、`Set`、`WeakMap` 或 `WeakSet` 的实例。
*   **基本类型包装对象**:  详细测试了 Javascript 的 `String`、`Number` 和 `Boolean` 对象的包装类型 (`String`、`Number`、`Boolean` 的构造函数创建的对象)。它验证了如何判断一个值是否为这些包装对象，以及如何从包装对象中获取原始值。
*   **基本类型值**: 测试了如何创建和操作 `v8::Number`、`v8::Date` 和 `v8::Boolean` 类型的 C++ 对象，并验证了它们与 Javascript 对应类型的行为。
*   **类型转换**: 测试了将 Javascript 值转换为数字和布尔值的 API 方法 (`NumberValue`, `BooleanValue`)。

**与 Javascript 的关系和示例：**

这些测试直接关联到 Javascript 的类型系统和基本数据类型。V8 引擎作为 Javascript 的运行时环境，需要提供 C++ API 来让开发者在 C++ 代码中操作和检查 Javascript 的值。

以下是一些功能对应的 Javascript 示例：

1. **整数处理**:
    ```javascript
    let value = 2**31; // 大于 INT32_MAX 的无符号整数
    // 在 Javascript 中，数字类型可以安全地表示这个值
    console.log(value);
    ```

2. **原生错误对象**:
    ```javascript
    try {
      eval("#"); // 触发一个 SyntaxError
    } catch (e) {
      console.log(e instanceof SyntaxError); // true
    }
    ```

3. **生成器函数和对象**:
    ```javascript
    function* gen() {
      yield 1;
    }
    let generatorFunction = gen;
    let generatorObject = gen();

    console.log(typeof generatorFunction === 'function'); // true
    console.log(generatorFunction.constructor.name === 'GeneratorFunction'); // true
    console.log(typeof generatorObject === 'object'); // true
    console.log(generatorObject.constructor.name === 'Generator'); // true
    ```

4. **异步函数**:
    ```javascript
    async function foo() {
      return 1;
    }
    console.log(foo instanceof Function); // true
    console.log(foo.constructor.name === 'AsyncFunction'); // true
    ```

5. **arguments 对象**:
    ```javascript
    function test() {
      console.log(arguments);
      console.log(typeof arguments === 'object'); // true
    }
    test(1, 2, 3);
    ```

6. **Map 和 Set 对象**:
    ```javascript
    let map = new Map();
    let set = new Set();
    let weakMap = new WeakMap();
    let weakSet = new WeakSet();

    console.log(map instanceof Map);    // true
    console.log(set instanceof Set);    // true
    console.log(weakMap instanceof WeakMap); // true
    console.log(weakSet instanceof WeakSet); // true
    ```

7. **基本类型包装对象**:
    ```javascript
    let strObj = new String("test");
    let numObj = new Number(42);
    let boolObj = new Boolean(true);

    console.log(typeof strObj === 'object'); // true
    console.log(strObj instanceof String);   // true
    console.log(typeof numObj === 'object'); // true
    console.log(numObj instanceof Number);   // true
    console.log(typeof boolObj === 'object'); // true
    console.log(boolObj instanceof Boolean);  // true

    let strPrimitive = "test";
    let numPrimitive = 42;
    let boolPrimitive = true;

    console.log(typeof strPrimitive === 'string'); // true
    console.log(typeof numPrimitive === 'number'); // true
    console.log(typeof boolPrimitive === 'boolean'); // true
    ```

8. **基本类型值**:
    ```javascript
    let num = 3.14;
    let date = new Date();
    let bool = true;

    console.log(typeof num === 'number');  // true
    console.log(date instanceof Date);    // true
    console.log(typeof bool === 'boolean'); // true
    ```

9. **类型转换**:
    ```javascript
    let str = "3.14";
    let boolTrue = true;
    let boolFalse = false;

    console.log(Number(str));      // 3.14
    console.log(Number(boolTrue)); // 1
    console.log(Number(boolFalse)); // 0

    console.log(Boolean(0));       // false
    console.log(Boolean(1));       // true
    console.log(Boolean(""));      // false
    console.log(Boolean("hello")); // true
    ```

总而言之，这部分 C++ 代码是 V8 引擎内部测试其 C++ API 功能的重要组成部分，确保了 C++ 代码能够正确地操作和理解 Javascript 的基本类型和对象。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共18部分，请归纳一下它的功能

"""
pe scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  uint32_t INT32_MAX_AS_UINT = (1U << 31) - 1;
  uint32_t value = INT32_MAX_AS_UINT + 1;
  CHECK(value > INT32_MAX_AS_UINT);  // No overflow.

  Local<v8::Integer> value_obj = v8::Integer::NewFromUnsigned(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(IsNativeError) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> syntax_error = CompileRun(
      "var out = 0; try { eval(\"#\"); } catch(x) { out = x; } out; ");
  CHECK(syntax_error->IsNativeError());
  v8::Local<Value> not_error = CompileRun("{a:42}");
  CHECK(!not_error->IsNativeError());
  v8::Local<Value> not_object = CompileRun("42");
  CHECK(!not_object->IsNativeError());
}


THREADED_TEST(IsGeneratorFunctionOrObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun("function *gen() { yield 1; }\nfunction func() {}");
  v8::Local<Value> gen = CompileRun("gen");
  v8::Local<Value> genObj = CompileRun("gen()");
  v8::Local<Value> object = CompileRun("{a:42}");
  v8::Local<Value> func = CompileRun("func");

  CHECK(gen->IsGeneratorFunction());
  CHECK(gen->IsFunction());
  CHECK(!gen->IsGeneratorObject());

  CHECK(!genObj->IsGeneratorFunction());
  CHECK(!genObj->IsFunction());
  CHECK(genObj->IsGeneratorObject());

  CHECK(!object->IsGeneratorFunction());
  CHECK(!object->IsFunction());
  CHECK(!object->IsGeneratorObject());

  CHECK(!func->IsGeneratorFunction());
  CHECK(func->IsFunction());
  CHECK(!func->IsGeneratorObject());
}

THREADED_TEST(IsAsyncFunction) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  CompileRun("async function foo() {}");
  v8::Local<Value> foo = CompileRun("foo");

  CHECK(foo->IsAsyncFunction());
  CHECK(foo->IsFunction());
  CHECK(!foo->IsGeneratorFunction());
  CHECK(!foo->IsGeneratorObject());

  CompileRun("function bar() {}");
  v8::Local<Value> bar = CompileRun("bar");

  CHECK(!bar->IsAsyncFunction());
  CHECK(bar->IsFunction());
}

THREADED_TEST(ArgumentsObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> arguments_object =
      CompileRun("var out = 0; (function(){ out = arguments; })(1,2,3); out;");
  CHECK(arguments_object->IsArgumentsObject());
  v8::Local<Value> array = CompileRun("[1,2,3]");
  CHECK(!array->IsArgumentsObject());
  v8::Local<Value> object = CompileRun("{a:42}");
  CHECK(!object->IsArgumentsObject());
}


THREADED_TEST(IsMapOrSet) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> map = CompileRun("new Map()");
  v8::Local<Value> set = CompileRun("new Set()");
  v8::Local<Value> weak_map = CompileRun("new WeakMap()");
  v8::Local<Value> weak_set = CompileRun("new WeakSet()");
  CHECK(map->IsMap());
  CHECK(set->IsSet());
  CHECK(weak_map->IsWeakMap());
  CHECK(weak_set->IsWeakSet());

  CHECK(!map->IsSet());
  CHECK(!map->IsWeakMap());
  CHECK(!map->IsWeakSet());

  CHECK(!set->IsMap());
  CHECK(!set->IsWeakMap());
  CHECK(!set->IsWeakSet());

  CHECK(!weak_map->IsMap());
  CHECK(!weak_map->IsSet());
  CHECK(!weak_map->IsWeakSet());

  CHECK(!weak_set->IsMap());
  CHECK(!weak_set->IsSet());
  CHECK(!weak_set->IsWeakMap());

  v8::Local<Value> object = CompileRun("{a:42}");
  CHECK(!object->IsMap());
  CHECK(!object->IsSet());
  CHECK(!object->IsWeakMap());
  CHECK(!object->IsWeakSet());
}


THREADED_TEST(StringObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> boxed_string = CompileRun("new String(\"test\")");
  CHECK(boxed_string->IsStringObject());
  v8::Local<Value> unboxed_string = CompileRun("\"test\"");
  CHECK(!unboxed_string->IsStringObject());
  v8::Local<Value> boxed_not_string = CompileRun("new Number(42)");
  CHECK(!boxed_not_string->IsStringObject());
  v8::Local<Value> not_object = CompileRun("0");
  CHECK(!not_object->IsStringObject());
  v8::Local<v8::StringObject> as_boxed = boxed_string.As<v8::StringObject>();
  CHECK(!as_boxed.IsEmpty());
  Local<v8::String> the_string = as_boxed->ValueOf();
  CHECK(!the_string.IsEmpty());
  ExpectObject("\"test\"", the_string);
  v8::Local<v8::Value> new_boxed_string =
      v8::StringObject::New(CcTest::isolate(), the_string);
  CHECK(new_boxed_string->IsStringObject());
  as_boxed = new_boxed_string.As<v8::StringObject>();
  the_string = as_boxed->ValueOf();
  CHECK(!the_string.IsEmpty());
  ExpectObject("\"test\"", the_string);
}


TEST(StringObjectDelete) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<Value> boxed_string = CompileRun("new String(\"test\")");
  CHECK(boxed_string->IsStringObject());
  v8::Local<v8::Object> str_obj = boxed_string.As<v8::Object>();
  CHECK(!str_obj->Delete(context.local(), 2).FromJust());
  CHECK(!str_obj->Delete(context.local(), v8_num(2)).FromJust());
}


THREADED_TEST(NumberObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> boxed_number = CompileRun("new Number(42)");
  CHECK(boxed_number->IsNumberObject());
  v8::Local<Value> unboxed_number = CompileRun("42");
  CHECK(!unboxed_number->IsNumberObject());
  v8::Local<Value> boxed_not_number = CompileRun("new Boolean(false)");
  CHECK(!boxed_not_number->IsNumberObject());
  v8::Local<v8::NumberObject> as_boxed = boxed_number.As<v8::NumberObject>();
  CHECK(!as_boxed.IsEmpty());
  double the_number = as_boxed->ValueOf();
  CHECK_EQ(42.0, the_number);
  v8::Local<v8::Value> new_boxed_number =
      v8::NumberObject::New(env->GetIsolate(), 43);
  CHECK(new_boxed_number->IsNumberObject());
  as_boxed = new_boxed_number.As<v8::NumberObject>();
  the_number = as_boxed->ValueOf();
  CHECK_EQ(43.0, the_number);
}

THREADED_TEST(BigIntObject) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context(env.local());
  v8::Local<Value> boxed_bigint = CompileRun("new Object(42n)");
  CHECK(!boxed_bigint->IsBigInt());
  CHECK(boxed_bigint->IsBigIntObject());
  v8::Local<Value> unboxed_bigint = CompileRun("42n");
  CHECK(unboxed_bigint->IsBigInt());
  CHECK(!unboxed_bigint->IsBigIntObject());
  v8::Local<v8::BigIntObject> as_boxed = boxed_bigint.As<v8::BigIntObject>();
  CHECK(!as_boxed.IsEmpty());
  v8::Local<v8::BigInt> unpacked = as_boxed->ValueOf();
  CHECK(!unpacked.IsEmpty());
  v8::Local<v8::Value> new_boxed_bigint = v8::BigIntObject::New(isolate, 43);
  CHECK(new_boxed_bigint->IsBigIntObject());
  v8::Local<v8::Value> new_unboxed_bigint = v8::BigInt::New(isolate, 44);
  CHECK(new_unboxed_bigint->IsBigInt());

  // Test functionality inherited from v8::Value.
  CHECK(unboxed_bigint->BooleanValue(isolate));
  v8::Local<v8::String> string =
      unboxed_bigint->ToString(context).ToLocalChecked();
  CHECK_EQ(0, strcmp("42", *v8::String::Utf8Value(isolate, string)));

  // IntegerValue throws.
  CHECK(unboxed_bigint->IntegerValue(context).IsNothing());
}

THREADED_TEST(BooleanObject) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<Value> boxed_boolean = CompileRun("new Boolean(true)");
  CHECK(boxed_boolean->IsBooleanObject());
  v8::Local<Value> unboxed_boolean = CompileRun("true");
  CHECK(!unboxed_boolean->IsBooleanObject());
  v8::Local<Value> boxed_not_boolean = CompileRun("new Number(42)");
  CHECK(!boxed_not_boolean->IsBooleanObject());
  v8::Local<v8::BooleanObject> as_boxed = boxed_boolean.As<v8::BooleanObject>();
  CHECK(!as_boxed.IsEmpty());
  bool the_boolean = as_boxed->ValueOf();
  CHECK(the_boolean);
  v8::Local<v8::Value> boxed_true =
      v8::BooleanObject::New(env->GetIsolate(), true);
  v8::Local<v8::Value> boxed_false =
      v8::BooleanObject::New(env->GetIsolate(), false);
  CHECK(boxed_true->IsBooleanObject());
  CHECK(boxed_false->IsBooleanObject());
  as_boxed = boxed_true.As<v8::BooleanObject>();
  CHECK(as_boxed->ValueOf());
  as_boxed = boxed_false.As<v8::BooleanObject>();
  CHECK(!as_boxed->ValueOf());
}


THREADED_TEST(PrimitiveAndWrappedBooleans) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<Value> primitive_false = Boolean::New(isolate, false);
  CHECK(primitive_false->IsBoolean());
  CHECK(!primitive_false->IsBooleanObject());
  CHECK(!primitive_false->BooleanValue(isolate));
  CHECK(!primitive_false->IsTrue());
  CHECK(primitive_false->IsFalse());

  Local<Value> false_value = BooleanObject::New(isolate, false);
  CHECK(!false_value->IsBoolean());
  CHECK(false_value->IsBooleanObject());
  CHECK(false_value->BooleanValue(isolate));
  CHECK(!false_value->IsTrue());
  CHECK(!false_value->IsFalse());

  Local<BooleanObject> false_boolean_object = false_value.As<BooleanObject>();
  CHECK(!false_boolean_object->IsBoolean());
  CHECK(false_boolean_object->IsBooleanObject());
  CHECK(false_boolean_object->BooleanValue(isolate));
  CHECK(!false_boolean_object->ValueOf());
  CHECK(!false_boolean_object->IsTrue());
  CHECK(!false_boolean_object->IsFalse());

  Local<Value> primitive_true = Boolean::New(isolate, true);
  CHECK(primitive_true->IsBoolean());
  CHECK(!primitive_true->IsBooleanObject());
  CHECK(primitive_true->BooleanValue(isolate));
  CHECK(primitive_true->IsTrue());
  CHECK(!primitive_true->IsFalse());

  Local<Value> true_value = BooleanObject::New(isolate, true);
  CHECK(!true_value->IsBoolean());
  CHECK(true_value->IsBooleanObject());
  CHECK(true_value->BooleanValue(isolate));
  CHECK(!true_value->IsTrue());
  CHECK(!true_value->IsFalse());

  Local<BooleanObject> true_boolean_object = true_value.As<BooleanObject>();
  CHECK(!true_boolean_object->IsBoolean());
  CHECK(true_boolean_object->IsBooleanObject());
  CHECK(true_boolean_object->BooleanValue(isolate));
  CHECK(true_boolean_object->ValueOf());
  CHECK(!true_boolean_object->IsTrue());
  CHECK(!true_boolean_object->IsFalse());
}


THREADED_TEST(Number) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  double PI = 3.1415926;
  Local<v8::Number> pi_obj = v8::Number::New(env->GetIsolate(), PI);
  CHECK_EQ(PI, pi_obj->NumberValue(env.local()).FromJust());
}


THREADED_TEST(ToNumber) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<String> str = v8_str("3.1415926");
  CHECK_EQ(3.1415926, str->NumberValue(env.local()).FromJust());
  v8::Local<v8::Boolean> t = v8::True(isolate);
  CHECK_EQ(1.0, t->NumberValue(env.local()).FromJust());
  v8::Local<v8::Boolean> f = v8::False(isolate);
  CHECK_EQ(0.0, f->NumberValue(env.local()).FromJust());
}


THREADED_TEST(Date) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  double PI = 3.1415926;
  Local<Value> date = v8::Date::New(env.local(), PI).ToLocalChecked();
  CHECK_EQ(3.0, date->NumberValue(env.local()).FromJust());
  CHECK(date.As<v8::Date>()
            ->Set(env.local(), v8_str("property"),
                  v8::Integer::New(env->GetIsolate(), 42))
            .FromJust());
  CHECK_EQ(42, date.As<v8::Date>()
                   ->Get(env.local(), v8_str("property"))
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}


THREADED_TEST(Boolean) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Boolean> t = v8::True(isolate);
  CHECK(t->Value());
  v8::Local<v8::Boolean> f = v8::False(isolate);
  CHECK(!f->Value());
  v8::Local<v8::Primitive> u = v8::Undefined(isolate);
  CHECK(!u->BooleanValue(isolate));
  v8::Local<v8::Primitive> n = v8::Null(isolate);
  CHECK(!n->BooleanValue(isolate));
  v8::Local<String> str1 = v8_str("");
  CHECK(!str1->BooleanValue(isolate));
  v8::Local<String> str2 = v8_str("x");
  CHECK(str2->BooleanValue(isolate));
  CHECK(!v8::Number::New(isolate, 0)->BooleanValue(isolate));
  CHECK(v8::Number::New(isolate, -1)->BooleanValue(isolate));
  CHECK(v8::Number::New(isolate, 1)->BooleanValue(isolate));
  CHECK(v8::Number::New(isolate, 42)->BooleanValue(isolate));
  CHECK(!v8_compile("NaN")
             ->Run(env.local())
             .ToLocalChecked()
             ->BooleanValue(isolate));
}

static void DummyCallHandler(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(13.4));
}

static void GetM(Local<Name> name,
                 const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(876));
}

THREADED_TEST(GlobalPrototype) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> func_templ =
      v8::FunctionTemplate::New(isolate);
  func_templ->PrototypeTemplate()->Set(
      isolate, "dummy", v8::FunctionTemplate::New(isolate, DummyCallHandler));
  v8::Local<ObjectTemplate> templ = func_templ->InstanceTemplate();
  templ->Set(isolate, "x", v8_num(200));
  templ->SetNativeDataProperty(v8_str("m"), GetM);
  LocalContext env(nullptr, templ);
  v8::Local<Script> script(v8_compile("dummy()"));
  v8::Local<Value> result(script->Run(env.local()).ToLocalChecked());
  CHECK_EQ(13.4, result->NumberValue(env.local()).FromJust());
  CHECK_EQ(200, v8_run_int32value(v8_compile("x")));
  CHECK_EQ(876, v8_run_int32value(v8_compile("m")));
}


THREADED_TEST(ObjectTemplate) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> acc =
      v8::FunctionTemplate::New(isolate, Returns42);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("acc"),
                  acc->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  Local<v8::FunctionTemplate> fun = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> class_name = v8_str("the_class_name");
  fun->SetClassName(class_name);
  Local<ObjectTemplate> templ1 = ObjectTemplate::New(isolate, fun);
  templ1->Set(isolate, "x", v8_num(10));
  templ1->Set(isolate, "y", v8_num(13));
  templ1->Set(isolate, "foo", acc);
  Local<v8::Object> instance1 =
      templ1->NewInstance(env.local()).ToLocalChecked();
  CHECK(class_name->StrictEquals(instance1->GetConstructorName()));
  CHECK(env->Global()->Set(env.local(), v8_str("p"), instance1).FromJust());
  CHECK(CompileRun("(p.x == 10)")->BooleanValue(isolate));
  CHECK(CompileRun("(p.y == 13)")->BooleanValue(isolate));
  CHECK(CompileRun("(p.foo() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(p.foo == acc)")->BooleanValue(isolate));
  // Ensure that foo become a data field.
  CompileRun("p.foo = function() {}");
  Local<v8::FunctionTemplate> fun2 = v8::FunctionTemplate::New(isolate);
  fun2->PrototypeTemplate()->Set(isolate, "nirk", v8_num(123));
  Local<ObjectTemplate> templ2 = fun2->InstanceTemplate();
  templ2->Set(isolate, "a", v8_num(12));
  templ2->Set(isolate, "b", templ1);
  templ2->Set(isolate, "bar", acc);
  templ2->SetAccessorProperty(v8_str("acc"), acc);
  Local<v8::Object> instance2 =
      templ2->NewInstance(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("q"), instance2).FromJust());
  CHECK(CompileRun("(q.nirk == 123)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.a == 12)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b.x == 10)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b.y == 13)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b.foo() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b.foo === acc)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.b !== p)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.acc == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.bar() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q.bar == acc)")->BooleanValue(isolate));

  instance2 = templ2->NewInstance(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("q2"), instance2).FromJust());
  CHECK(CompileRun("(q2.nirk == 123)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.a == 12)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.b.x == 10)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.b.y == 13)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.b.foo() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.b.foo === acc)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.acc == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.bar() == 42)")->BooleanValue(isolate));
  CHECK(CompileRun("(q2.bar === acc)")->BooleanValue(isolate));

  CHECK(CompileRun("(q.b !== q2.b)")->BooleanValue(isolate));
  CHECK(CompileRun("q.b.x = 17; (q2.b.x == 10)")->BooleanValue(isolate));
  CHECK(CompileRun("desc1 = Object.getOwnPropertyDescriptor(q, 'acc');"
                   "(desc1.get === acc)")
            ->BooleanValue(isolate));
  CHECK(CompileRun("desc2 = Object.getOwnPropertyDescriptor(q2, 'acc');"
                   "(desc2.get === acc)")
            ->BooleanValue(isolate));
}

THREADED_TEST(IntegerValue) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  CHECK_EQ(0, CompileRun("undefined")->IntegerValue(env.local()).FromJust());
}

static void GetNirk(Local<Name> name,
                    const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(900));
}

static void GetRino(Local<Name> name,
                    const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(560));
}

enum ObjectInstantiationMode {
  // Create object using ObjectTemplate::NewInstance.
  ObjectTemplate_NewInstance,
  // Create object using FunctionTemplate::NewInstance on constructor.
  Constructor_GetFunction_NewInstance,
  // Create object using new operator on constructor.
  Constructor_GetFunction_New
};

// Test object instance creation using a function template with an instance
// template inherited from another function template with accessors and data
// properties in prototype template.
static void TestObjectTemplateInheritedWithPrototype(
    ObjectInstantiationMode mode) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_A = v8::FunctionTemplate::New(isolate);
  fun_A->SetClassName(v8_str("A"));
  v8::Local<v8::ObjectTemplate> prototype_templ = fun_A->PrototypeTemplate();
  prototype_templ->Set(isolate, "a", v8_num(113));
  prototype_templ->SetNativeDataProperty(v8_str("nirk"), GetNirk);
  prototype_templ->Set(isolate, "b", v8_num(153));

  Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> class_name = v8_str("B");
  fun_B->SetClassName(class_name);
  fun_B->Inherit(fun_A);
  prototype_templ = fun_B->PrototypeTemplate();
  prototype_templ->Set(isolate, "c", v8_num(713));
  prototype_templ->SetNativeDataProperty(v8_str("rino"), GetRino);
  prototype_templ->Set(isolate, "d", v8_num(753));

  Local<ObjectTemplate> templ = fun_B->InstanceTemplate();
  templ->Set(isolate, "x", v8_num(10));
  templ->Set(isolate, "y", v8_num(13));

  // Perform several iterations to trigger creation from cached boilerplate.
  for (int i = 0; i < 3; i++) {
    Local<v8::Object> instance;
    switch (mode) {
      case ObjectTemplate_NewInstance:
        instance = templ->NewInstance(env.local()).ToLocalChecked();
        break;

      case Constructor_GetFunction_NewInstance: {
        Local<v8::Function> function_B =
            fun_B->GetFunction(env.local()).ToLocalChecked();
        instance = function_B->NewInstance(env.local()).ToLocalChecked();
        break;
      }
      case Constructor_GetFunction_New: {
        Local<v8::Function> function_B =
            fun_B->GetFunction(env.local()).ToLocalChecked();
        if (i == 0) {
          CHECK(env->Global()
                    ->Set(env.local(), class_name, function_B)
                    .FromJust());
        }
        instance =
            CompileRun("new B()")->ToObject(env.local()).ToLocalChecked();
        break;
      }
      default:
        UNREACHABLE();
    }

    CHECK(class_name->StrictEquals(instance->GetConstructorName()));
    CHECK(env->Global()->Set(env.local(), v8_str("o"), instance).FromJust());

    CHECK_EQ(10, CompileRun("o.x")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(13, CompileRun("o.y")->IntegerValue(env.local()).FromJust());

    CHECK_EQ(113, CompileRun("o.a")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(900, CompileRun("o.nirk")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(153, CompileRun("o.b")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(713, CompileRun("o.c")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(560, CompileRun("o.rino")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(753, CompileRun("o.d")->IntegerValue(env.local()).FromJust());
  }
}

THREADED_TEST(TestObjectTemplateInheritedWithAccessorsInPrototype1) {
  TestObjectTemplateInheritedWithPrototype(ObjectTemplate_NewInstance);
}

THREADED_TEST(TestObjectTemplateInheritedWithAccessorsInPrototype2) {
  TestObjectTemplateInheritedWithPrototype(Constructor_GetFunction_NewInstance);
}

THREADED_TEST(TestObjectTemplateInheritedWithAccessorsInPrototype3) {
  TestObjectTemplateInheritedWithPrototype(Constructor_GetFunction_New);
}

// Test object instance creation using a function template without an instance
// template inherited from another function template.
static void TestObjectTemplateInheritedWithoutInstanceTemplate(
    ObjectInstantiationMode mode) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_A = v8::FunctionTemplate::New(isolate);
  fun_A->SetClassName(v8_str("A"));

  Local<ObjectTemplate> templ_A = fun_A->InstanceTemplate();
  templ_A->SetNativeDataProperty(v8_str("nirk"), GetNirk);
  templ_A->SetNativeDataProperty(v8_str("rino"), GetRino);

  Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> class_name = v8_str("B");
  fun_B->SetClassName(class_name);
  fun_B->Inherit(fun_A);

  // Perform several iterations to trigger creation from cached boilerplate.
  for (int i = 0; i < 3; i++) {
    Local<v8::Object> instance;
    switch (mode) {
      case Constructor_GetFunction_NewInstance: {
        Local<v8::Function> function_B =
            fun_B->GetFunction(env.local()).ToLocalChecked();
        instance = function_B->NewInstance(env.local()).ToLocalChecked();
        break;
      }
      case Constructor_GetFunction_New: {
        Local<v8::Function> function_B =
            fun_B->GetFunction(env.local()).ToLocalChecked();
        if (i == 0) {
          CHECK(env->Global()
                    ->Set(env.local(), class_name, function_B)
                    .FromJust());
        }
        instance =
            CompileRun("new B()")->ToObject(env.local()).ToLocalChecked();
        break;
      }
      default:
        UNREACHABLE();
    }

    CHECK(class_name->StrictEquals(instance->GetConstructorName()));
    CHECK(env->Global()->Set(env.local(), v8_str("o"), instance).FromJust());

    CHECK_EQ(900, CompileRun("o.nirk")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(560, CompileRun("o.rino")->IntegerValue(env.local()).FromJust());
  }
}

THREADED_TEST(TestDataTypeChecks) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Data> values[] = {
      v8::Undefined(isolate),
      v8::Null(isolate),
      v8::True(isolate),
      v8::Integer::New(isolate, 10),
      v8::Number::New(isolate, 3.14),
      v8::BigInt::NewFromUnsigned(isolate, 10),
      v8::Symbol::New(isolate),
      v8::String::NewFromUtf8Literal(isolate, "hello"),
  };
  for (auto x : values) {
    CHECK(!x->IsModule());
    CHECK(x->IsValue());
    CHECK(!x->IsPrivate());
    CHECK(!x->IsObjectTemplate());
    CHECK(!x->IsFunctionTemplate());
    v8::Local<v8::Value>::Cast(x);
    x.As<v8::Value>();
  }

  v8::ScriptOrigin origin(v8_str(""), 0, 0, false, -1, Local<v8::Value>(),
                          false, false, true);
  v8::ScriptCompiler::Source source(v8::String::NewFromUtf8Literal(isolate, ""),
                                    origin);
  v8::Local<v8::Data> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  CHECK(module->IsModule());
  CHECK(!module->IsValue());
  CHECK(!module->IsPrivate());
  CHECK(!module->IsObjectTemplate());
  CHECK(!module->IsFunctionTemplate());
  v8::Local<v8::Module>::Cast(module);
  module.As<v8::Module>();

  v8::Local<v8::Data> p = v8::Private::New(isolate);
  CHECK(!p->IsModule());
  CHECK(!p->IsValue());
  CHECK(p->IsPrivate());
  CHECK(!p->IsObjectTemplate());
  CHECK(!p->IsFunctionTemplate());
  CHECK(!(*reinterpret_cast<Local<Value>*>(&p))->IsSymbol());
  v8::Local<v8::Private>::Cast(p);

  v8::Local<v8::Data> otmpl = v8::ObjectTemplate::New(isolate);
  CHECK(!otmpl->IsModule());
  CHECK(!otmpl->IsValue());
  CHECK(!otmpl->IsPrivate());
  CHECK(otmpl->IsObjectTemplate());
  CHECK(!otmpl->IsFunctionTemplate());

  v8::Local<v8::Data> ftmpl = v8::FunctionTemplate::New(isolate);
  CHECK(!ftmpl->IsModule());
  CHECK(!ftmpl->IsValue());
  CHECK(!ftmpl->IsPrivate());
  CHECK(!ftmpl->IsObjectTemplate());
  CHECK(ftmpl->IsFunctionTemplate());
}

THREADED_TEST(TestObjectTemplateInheritedWithPrototype1) {
  TestObjectTemplateInheritedWithoutInstanceTemplate(
      Constructor_GetFunction_NewInstance);
}

THREADED_TEST(TestObjectTemplateInheritedWithPrototype2) {
  TestObjectTemplateInheritedWithoutInstanceTemplate(
      Constructor_GetFunction_New);
}

THREADED_TEST(TestObjectTemplateClassInheritance) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_A = v8::FunctionTemplate::New(isolate);
  fun_A->SetClassName(v8_str("A"));

  Local<ObjectTemplate> templ_A = fun_A->InstanceTemplate();
  templ_A->SetNativeDataProperty(v8_str("nirk"), GetNirk);
  templ_A->SetNativeDataProperty(v8_str("rino"), GetRino);

  Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> class_name = v8_str("B");
  fun_B->SetClassName(class_name);
  fun_B->Inherit(fun_A);

  v8::Local<v8::String> subclass_name = v8_str("C");
  v8::Local<v8::Object> b_proto;
  v8::Local<v8::Object> c_proto;
  // Perform several iterations to make sure the cache doesn't break
  // subclassing.
  for (int i = 0; i < 3; i++) {
    Local<v8::Function> function_B =
        fun_B->GetFunction(env.local()).ToLocalChecked();
    if (i == 0) {
      CHECK(env->Global()->Set(env.local(), class_name, function_B).FromJust());
      CompileRun("class C extends B {}");
      b_proto =
          CompileRun("B.prototype")->ToObject(env.local()).ToLocalChecked();
      c_proto =
          CompileRun("C.prototype")->ToObject(env.local()).ToLocalChecked();
      CHECK(b_proto->Equals(env.local(), c_proto->GetPrototypeV2()).FromJust());
    }
    Local<v8::Object> instance =
        CompileRun("new C()")->ToObject(env.local()).ToLocalChecked();
    CHECK(c_proto->Equals(env.local(), instance->GetPrototypeV2()).FromJust());

    CHECK(subclass_name->StrictEquals(instance->GetConstructorName()));
    CHECK(env->Global()->Set(env.local(), v8_str("o"), instance).FromJust());

    CHECK_EQ(900, CompileRun("o.nirk")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(560, CompileRun("o.rino")->IntegerValue(env.local()).FromJust());
  }
}

namespace {
v8::Intercepted NamedPropertyGetterWhichReturns42(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(42));
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(TestObjectTemplateReflectConstruct) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_B = v8::FunctionTemplate::New(isolate);
  fun_B->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(NamedPropertyGetterWhichReturns42));
  v8::Local<v8::String> class_name = v8_str("B");
  fun_B->SetClassName(class_name);

  v8::Local<v8::String> subclass_name = v8_str("C");
  v8::Local<v8::Object> c_proto;
  // Perform several iterations to make sure the cache doesn't break
  // subclassing.
  for (int i = 0; i < 3; i++) {
    Local<v8::Function> function_B =
        fun_B->GetFunction(env.local()).ToLocalChecked();
    if (i == 0) {
      CHECK(env->Global()->Set(env.local(), class_name, function_B).FromJust());
      CompileRun("function C() {}");
      c_proto =
          CompileRun("C.prototype")->ToObject(env.local()).ToLocalChecked();
    }
    Local<v8::Object> instance = CompileRun("Reflect.construct(B, [], C)")
                                     ->ToObject(env.local())
                                     .ToLocalChecked();
    CHECK(c_proto->Equals(env.local(), instance->GetPrototypeV2()).FromJust());

    CHECK(subclass_name->StrictEquals(instance->GetConstructorName()));
    CHECK(env->Global()->Set(env.local(), v8_str("o"), instance).FromJust());

    CHECK_EQ(42, CompileRun("o.nirk")->IntegerValue(env.local()).FromJust());
    CHECK_EQ(42, CompileRun("o.rino")->IntegerValue(env.local()).FromJust());
  }
}

static void GetFlabby(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(17.2));
}

static void GetKnurd(Local<Name> property,
                     const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(15.2));
}

THREADED_TEST(DescriptorInheritance) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> super = v8::FunctionTemplate::New(isolate);
  super->PrototypeTemplate()->Set(isolate, "flabby",
                                  v8::FunctionTemplate::New(isolate,
                                                            GetFlabby));
  super->PrototypeTemplate()->Set(isolate, "PI", v8_num(3.14));

  super->InstanceTemplate()->SetNativeDataProperty(v8_str("knurd"), GetKnurd);

  v8::Local<v8::FunctionTemplate> base1 = v8::FunctionTemplate::New(isolate);
  base1->Inherit(super);
  base1->PrototypeTemplate()->Set(isolate, "v1", v8_num(20.1));

  v8::Local<v8::FunctionTemplate> base2 = v8::FunctionTemplate::New(isolate);
  base2->Inherit(super);
  base2->PrototypeTemplate()->Set(isolate, "v2", v8_num(10.1));

  LocalContext env;

  CHECK(env->Global()
            ->Set(env.local(), v8_str("s"),
                  super->GetFunction(env.local()).ToLocalChecked())
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("base1"),
                  base1->GetFunction(env.local()).ToLocalChecked())
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("base2"),
                  base2->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  // Checks right __proto__ chain.
  CHECK(CompileRun("base1.prototype.__proto__ == s.prototype")
            ->BooleanValue(isolate));
  CHECK(CompileRun("base2.prototype.__proto__ == s.prototype")
            ->BooleanValue(isolate));

  CHECK(v8_compile("s.prototype.PI == 3.14")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));

  // Instance accessor should not be visible on function object or its prototype
  CHECK(CompileRun("s.knurd == undefined")->BooleanValue(isolate));
  CHECK(CompileRun("s.prototype.knurd == undefined")->BooleanValue(isolate));
  CHECK(
      CompileRun("base1.prototype.knurd == undefined")->BooleanValue(isolate));

  CHECK(env->Global()
            ->Set(env.local(), v8_str("obj"), base1->GetFunction(env.local())
                                                  .ToLocalChecked()
                                                  ->NewInstance(env.local())
                                                  .ToLocalChecked())
            .FromJust());
  CHECK_EQ(17.2,
           CompileRun("obj.flabby()")->NumberValue(env.local()).FromJust());
  CHECK(CompileRun("'flabby' in obj")->BooleanValue(isolate));
  CHECK_EQ(15.2, CompileRun("obj.knurd")->NumberValue(env.local()).FromJust());
  CHECK(CompileRun("'knurd' in obj")->BooleanValue(isolate));
  CHECK_EQ(20.1, CompileRun("obj.v1")->NumberValue(env.local()).FromJust());

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
"""


```