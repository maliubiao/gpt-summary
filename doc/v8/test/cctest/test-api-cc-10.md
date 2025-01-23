Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. The summary should also address several specific points:

1. **Core Functionality:** What does this code do?
2. **Torque Source:** Is this a Torque file (indicated by a `.tq` extension)?
3. **JavaScript Relation:** If it interacts with JavaScript, provide JavaScript examples.
4. **Logic Reasoning:** Provide examples of input and output if there's logical deduction.
5. **Common Programming Errors:**  Illustrate potential errors.
6. **Part Number:**  Acknowledge that this is part 11 of 36.

Let's break down the code to understand its purpose. It seems to contain a series of test cases for the V8 JavaScript engine's C++ API. These tests cover various aspects of the API, including:

- **UTF-16 String Handling:** Testing how V8 handles UTF-16 encoded strings, including surrogate pairs and string lengths.
- **Symbol Creation and Comparison:** Verifying the creation and comparison of internalized strings (symbols).
- **String Conversion to Array Indices:** Checking the conversion of strings and numbers to valid array indices.
- **Exception Handling:**  Testing the creation of different types of JavaScript errors and how V8 handles uncaught exceptions.
- **Property Accessors:**  Demonstrating the use of getter and setter accessors for object properties.
- **Security Checks:**  Testing V8's security mechanisms for cross-context access and property manipulation.
- **Context Management:**  Exploring the creation, manipulation, and detachment of V8 contexts.

Now, let's address the user's specific requests.

**Plan:**

1. **Summarize the overall functionality:**  Focus on it being a test suite for the V8 C++ API.
2. **Check for `.tq` extension:**  Clearly state that it's a `.cc` file, not `.tq`.
3. **Identify JavaScript relations and provide examples:**  Most tests interact with JavaScript code through `CompileRun`. Extract representative examples.
4. **Look for logic reasoning and provide input/output:**  Some tests, like `Utf16Helper` and `ToArrayIndex`, involve logical transformations. Provide simple examples.
5. **Identify common programming errors:**  Point out potential errors related to incorrect string handling, security violations, and context management based on the test cases.
6. **Acknowledge the part number.**
这是一个V8源代码文件 `v8/test/cctest/test-api.cc` 的第 11 部分，主要功能是 **测试 V8 JavaScript 引擎的 C++ API 的各种功能，特别是与字符串（尤其是 UTF-16 编码）、符号、类型转换、异常处理、安全检查和上下文管理相关的 API 功能。**

**它不是一个 Torque 源代码文件。** 因为它的文件名以 `.cc` 结尾，而不是 `.tq`。

**它与 JavaScript 的功能有密切关系，因为它测试的是 V8 引擎提供的用于执行和操作 JavaScript 代码的 C++ API。**  以下是一些与代码片段中功能相关的 JavaScript 示例：

1. **UTF-16 字符串处理:**
   ```javascript
   // JavaScript 中创建包含代理对的字符串
   var str = '\uD801\uDC07'; // 长度为 1 的 Unicode 字符
   console.log(str.length); // 输出 1

   // JavaScript 中获取字符的 Unicode 编码单元
   console.log(str.charCodeAt(0)); // 输出 55745 (0xD801)
   console.log(str.charCodeAt(1)); // 输出 56327 (0xDC07)

   // JavaScript 中使用 substring
   var text = 'xabcdefy';
   var sub = text.substring(1, text.length - 1);
   console.log(sub); // 输出 "abcdef"
   ```

2. **符号 (Internalized String):**
   ```javascript
   // JavaScript 中的字符串字面量也会被引擎内部化 (在某些情况下)
   var str1 = "abc";
   var str2 = "abc";
   console.log(str1 === str2); // 输出 true (可能，取决于引擎的优化)
   ```

3. **将字符串转换为数组索引:**
   ```javascript
   console.log(Array.isArray(new Array("42"))); // 输出 true，长度为 1
   console.log(Array.isArray(new Array("42asdf"))); // 输出 true，长度为 1
   var arr = [];
   arr["42"] = "hello";
   console.log(arr.length); // 输出 0
   console.log(arr[42]); // 输出 "hello"
   ```

4. **异常处理:**
   ```javascript
   try {
     throw new RangeError("超出范围");
   } catch (e) {
     console.error(e.name); // 输出 "RangeError"
     console.error(e.message); // 输出 "超出范围"
   }
   ```

5. **属性访问器 (getter/setter):**
   ```javascript
   var obj = {
     _y: 0,
     get y() {
       return this._y * 10;
     },
     set y(value) {
       this._y = value / 10;
     }
   };
   obj.y = 120;
   console.log(obj.y); // 输出 120
   console.log(obj._y); // 输出 12
   ```

6. **安全检查和上下文:** 这些功能在 JavaScript 中不直接暴露，而是 V8 引擎内部管理的不同执行上下文之间的隔离。

**代码逻辑推理的例子（`Utf16Helper` 函数和相关的 `THREADED_TEST(Utf16String)`）：**

**假设输入:**
- `a` 数组: `["A", "B\uD800", "C", "D\uD801", "E", "F", "G\uD802", "H", "I"]`
- `alens` 数组: `[1, 1, 1, 1, 1, 1, 1, 1, 1]` (初始长度，但会根据代理对调整)

**代码逻辑:**
- 外层循环 `m` 从 0 到 8，内层循环 `n` 从 0 到 8。
- `a2` 存储 `a[m] + a[n]` 的结果。
- `b2` 存储 `b[m] + b[n]` 的结果（`b` 未定义，这是一个潜在的编程错误）。
- `c2` 存储去掉首尾 'x' 和 'y' 的字符串连接结果。
- `a2lens` 存储根据 `alens[m]` 和 `alens[n]` 计算出的长度，并会根据代理对进行调整。如果 `a[m]` 以高位代理项结尾，且 `a[n]` 以低位代理项开头，则 `utf` 减 2。

**假设输出 (部分 `a2` 和 `a2lens`):**

| m | n | a[m] | a[n] | a2[m*9 + n] | alens[m] | alens[n] | utf (before adjust) | Condition ((m % 3) == 1 && n >= 6) | utf (after adjust) | a2lens[m*9 + n] |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 0 | A | A | AA | 1 | 1 | 2 | false | 2 | 2 |
| 0 | 6 | A | G\uD802 | AG\uD802 | 1 | 1 | 2 | false | 2 | 2 |
| 1 | 0 | B\uD800 | A | B\uD800A | 1 | 1 | 2 | false | 2 | 2 |
| 1 | 6 | B\uD800 | G\uD802 | B\uD800G\uD802 | 1 | 1 | 2 | true | 0 | 0 |  *(这里因为 B\uD800 是高位代理项，G\uD802 也是高位代理项，不匹配，所以实际长度应该是 2)*
| 4 | 6 | E | G\uD802 | EG\uD802 | 1 | 1 | 2 | true | 0 | 0 | *(同上)*
| 7 | 6 | H | G\uD802 | HG\uD802 | 1 | 1 | 2 | true | 0 | 0 | *(同上)*

**涉及用户常见的编程错误:**

1. **未定义的变量使用 (`b` 数组):** 在 `Utf16Helper` 函数中使用了未定义的 `b` 数组，这会导致运行时错误或未预期的行为。

   ```c++
   "    b2.push(b[m] + b[n]);" // 'b' is not defined in the provided setup
   ```

2. **对代理对的长度计算不准确:**  开发者可能错误地认为代理对是两个独立的字符，而实际上它们组成一个 Unicode 字符。V8 的 API 提供了正确处理代理对的方法，但开发者需要注意区分编码单元和 Unicode 字符。

3. **字符串索引的错误假设:** 在 JavaScript 中，字符串的 `charCodeAt()` 方法返回指定索引处的 UTF-16 编码单元。对于代理对，需要两次调用才能获取完整的代码点。代码中的测试用例 (`Utf16Symbol`) 验证了这一点。

4. **跨上下文访问的安全问题:**  在多上下文 V8 环境中，不正确地共享或访问对象可能导致安全漏洞。测试用例 (`SecurityHandler`, `SecurityChecks` 等) 旨在验证 V8 的安全机制是否能够阻止非法的跨上下文访问。

5. **忘记处理异常:** 在调用 V8 API 时，某些操作可能会抛出异常。开发者需要使用 `TryCatch` 等机制来捕获和处理这些异常，否则可能导致程序崩溃。

**总结一下它的功能:**

作为 `v8/test/cctest/test-api.cc` 的一部分，这段代码片段专注于测试 V8 引擎 C++ API 中与字符串处理（特别是 UTF-16）、符号、类型转换（如字符串到数组索引）、异常创建和捕获、跨上下文安全以及上下文管理相关的核心功能。这些测试确保了 V8 提供的 API 的正确性和健壮性，以便开发者能够安全有效地在 C++ 代码中嵌入和操作 V8 JavaScript 引擎。这是整个测试套件中的一部分，用于验证 V8 引擎的各个方面。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
[5] -= 2;"  // Here the surrogate pairs match up.
      "var a2 = [];"
      "var b2 = [];"
      "var c2 = [];"
      "var a2lens = [];"
      "for (var m = 0; m < 9; m++) {"
      "  for (var n = 0; n < 9; n++) {"
      "    a2.push(a[m] + a[n]);"
      "    b2.push(b[m] + b[n]);"
      "    var newc = 'x' + c[m] + c[n] + 'y';"
      "    c2.push(newc.substring(1, newc.length - 1));"
      "    var utf = alens[m] + alens[n];"  // And here.
                                            // The 'n's that start with 0xDC..
                                            // are 6-8 The 'm's that end with
                                            // 0xD8.. are 1, 4 and 7
      "    if ((m % 3) == 1 && n >= 6) utf -= 2;"
      "    a2lens.push(utf);"
      "  }"
      "}");
  Utf16Helper(context, "a", "alens", 9);
  Utf16Helper(context, "a2", "a2lens", 81);
}


static bool SameSymbol(Local<String> s1, Local<String> s2) {
  i::DirectHandle<i::String> is1 = v8::Utils::OpenDirectHandle(*s1);
  i::DirectHandle<i::String> is2 = v8::Utils::OpenDirectHandle(*s2);
  return *is1 == *is2;
}


THREADED_TEST(Utf16Symbol) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  Local<String> symbol1 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "abc", v8::NewStringType::kInternalized);
  Local<String> symbol2 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "abc", v8::NewStringType::kInternalized);
  CHECK(SameSymbol(symbol1, symbol2));

  CompileRun(
      "var sym0 = 'benedictus';"
      "var sym0b = 'S\xC3\xB8ren';"
      "var sym1 = '\xED\xA0\x81\xED\xB0\x87';"
      "var sym2 = '\xF0\x90\x90\x88';"
      "var sym3 = 'x\xED\xA0\x81\xED\xB0\x87';"
      "var sym4 = 'x\xF0\x90\x90\x88';"
      "if (sym1.length != 2) throw sym1;"
      "if (sym1.charCodeAt(1) != 0xDC07) throw sym1.charCodeAt(1);"
      "if (sym2.length != 2) throw sym2;"
      "if (sym2.charCodeAt(1) != 0xDC08) throw sym2.charCodeAt(2);"
      "if (sym3.length != 3) throw sym3;"
      "if (sym3.charCodeAt(2) != 0xDC07) throw sym1.charCodeAt(2);"
      "if (sym4.length != 3) throw sym4;"
      "if (sym4.charCodeAt(2) != 0xDC08) throw sym2.charCodeAt(2);");
  Local<String> sym0 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "benedictus", v8::NewStringType::kInternalized);
  Local<String> sym0b = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "S\xC3\xB8ren", v8::NewStringType::kInternalized);
  Local<String> sym1 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "\xED\xA0\x81\xED\xB0\x87",
      v8::NewStringType::kInternalized);
  Local<String> sym2 =
      v8::String::NewFromUtf8Literal(context->GetIsolate(), "\xF0\x90\x90\x88",
                                     v8::NewStringType::kInternalized);
  Local<String> sym3 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "x\xED\xA0\x81\xED\xB0\x87",
      v8::NewStringType::kInternalized);
  Local<String> sym4 =
      v8::String::NewFromUtf8Literal(context->GetIsolate(), "x\xF0\x90\x90\x88",
                                     v8::NewStringType::kInternalized);
  v8::Local<v8::Object> global = context->Global();
  Local<Value> s0 =
      global->Get(context.local(), v8_str("sym0")).ToLocalChecked();
  Local<Value> s0b =
      global->Get(context.local(), v8_str("sym0b")).ToLocalChecked();
  Local<Value> s1 =
      global->Get(context.local(), v8_str("sym1")).ToLocalChecked();
  Local<Value> s2 =
      global->Get(context.local(), v8_str("sym2")).ToLocalChecked();
  Local<Value> s3 =
      global->Get(context.local(), v8_str("sym3")).ToLocalChecked();
  Local<Value> s4 =
      global->Get(context.local(), v8_str("sym4")).ToLocalChecked();
  CHECK(SameSymbol(sym0, Local<String>::Cast(s0)));
  CHECK(SameSymbol(sym0b, Local<String>::Cast(s0b)));
  CHECK(SameSymbol(sym1, Local<String>::Cast(s1)));
  CHECK(SameSymbol(sym2, Local<String>::Cast(s2)));
  CHECK(SameSymbol(sym3, Local<String>::Cast(s3)));
  CHECK(SameSymbol(sym4, Local<String>::Cast(s4)));
}


THREADED_TEST(Utf16MissingTrailing) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // Make sure it will go past the buffer, so it will call `WriteUtf16Slow`
  int size = 1024 * 64;
  uint8_t* buffer = new uint8_t[size];
  for (int i = 0; i < size; i += 4) {
    buffer[i] = 0xF0;
    buffer[i + 1] = 0x9D;
    buffer[i + 2] = 0x80;
    buffer[i + 3] = 0x9E;
  }

  // Now invoke the decoder without last 3 bytes
  v8::Local<v8::String> str =
      v8::String::NewFromUtf8(
          context->GetIsolate(), reinterpret_cast<char*>(buffer),
          v8::NewStringType::kNormal, size - 3).ToLocalChecked();
  USE(str);
  delete[] buffer;
}

START_ALLOW_USE_DEPRECATED()

THREADED_TEST(Utf16Trailing3Byte_Value) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Make sure it will go past the buffer, so it will call `WriteUtf16Slow`
  int size = 1024 * 63;
  uint8_t* buffer = new uint8_t[size];
  for (int i = 0; i < size; i += 3) {
    buffer[i] = 0xE2;
    buffer[i + 1] = 0x80;
    buffer[i + 2] = 0xA6;
  }

  // Now invoke the decoder without last 3 bytes
  v8::Local<v8::String> str =
      v8::String::NewFromUtf8(isolate, reinterpret_cast<char*>(buffer),
                              v8::NewStringType::kNormal, size)
          .ToLocalChecked();

  v8::String::Value value(isolate, str);
  CHECK_EQ(value.length(), size / 3);
  CHECK_EQ((*value)[value.length() - 1], 0x2026);

  delete[] buffer;
}

END_ALLOW_USE_DEPRECATED()

THREADED_TEST(Utf16Trailing3Byte_ValueView) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Make sure it will go past the buffer, so it will call `WriteUtf16Slow`
  int size = 1024 * 63;
  uint8_t* buffer = new uint8_t[size];
  for (int i = 0; i < size; i += 3) {
    buffer[i] = 0xE2;
    buffer[i + 1] = 0x80;
    buffer[i + 2] = 0xA6;
  }

  // Now invoke the decoder without last 3 bytes
  v8::Local<v8::String> str =
      v8::String::NewFromUtf8(isolate, reinterpret_cast<char*>(buffer),
                              v8::NewStringType::kNormal, size)
          .ToLocalChecked();

  v8::String::ValueView value(isolate, str);
  CHECK(!value.is_one_byte());
  CHECK_EQ(value.length(), size / 3);
  CHECK_EQ(value.data16()[value.length() - 1], 0x2026);

  delete[] buffer;
}

THREADED_TEST(ToArrayIndex) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<String> str = v8_str("42");
  v8::MaybeLocal<v8::Uint32> index = str->ToArrayIndex(context.local());
  CHECK(!index.IsEmpty());
  CHECK_EQ(42.0,
           index.ToLocalChecked()->Uint32Value(context.local()).FromJust());
  str = v8_str("42asdf");
  index = str->ToArrayIndex(context.local());
  CHECK(index.IsEmpty());
  str = v8_str("-42");
  index = str->ToArrayIndex(context.local());
  CHECK(index.IsEmpty());
  str = v8_str("4294967294");
  index = str->ToArrayIndex(context.local());
  CHECK(!index.IsEmpty());
  CHECK_EQ(4294967294.0,
           index.ToLocalChecked()->Uint32Value(context.local()).FromJust());
  v8::Local<v8::Number> num = v8::Number::New(isolate, 1);
  index = num->ToArrayIndex(context.local());
  CHECK(!index.IsEmpty());
  CHECK_EQ(1.0,
           index.ToLocalChecked()->Uint32Value(context.local()).FromJust());
  num = v8::Number::New(isolate, -1);
  index = num->ToArrayIndex(context.local());
  CHECK(index.IsEmpty());
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  index = obj->ToArrayIndex(context.local());
  CHECK(index.IsEmpty());
}

THREADED_TEST(ErrorConstruction) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  v8::Local<String> foo = v8_str("foo");
  v8::Local<String> message = v8_str("message");
  v8::Local<Value> range_error = v8::Exception::RangeError(foo);
  CHECK(range_error->IsObject());
  CHECK(range_error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
  v8::Local<Value> reference_error = v8::Exception::ReferenceError(foo);
  CHECK(reference_error->IsObject());
  CHECK(reference_error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
  v8::Local<Value> syntax_error = v8::Exception::SyntaxError(foo);
  CHECK(syntax_error->IsObject());
  CHECK(syntax_error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
  v8::Local<Value> type_error = v8::Exception::TypeError(foo);
  CHECK(type_error->IsObject());
  CHECK(type_error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
  v8::Local<Value> error = v8::Exception::Error(foo);
  CHECK(error->IsObject());
  CHECK(error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
}

THREADED_TEST(ExceptionCreateMessageLength) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // Test that the message is not truncated.
  TryCatch try_catch(context->GetIsolate());
  CompileRun(
      "var message = 'm';"
      "while (message.length < 1000) message += message;"
      "throw message;");
  CHECK(try_catch.HasCaught());

  CHECK_LT(1000, try_catch.Message()->Get()->Length());
}

static void YGetter(Local<Name> name,
                    const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(10));
}

static void YSetter(Local<Name> name, Local<Value> value,
                    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Local<Object> this_obj = info.This().As<Object>();
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  if (this_obj->Has(context, name).FromJust())
    this_obj->Delete(context, name).FromJust();
  CHECK(this_obj->Set(context, name, value).FromJust());
}

THREADED_TEST(DeleteAccessor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("y"), YGetter, YSetter);
  LocalContext context;
  v8::Local<v8::Object> holder =
      obj->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("holder"), holder)
            .FromJust());
  v8::Local<Value> result =
      CompileRun("holder.y = 11; holder.y = 12; holder.y");
  CHECK_EQ(12u, result->Uint32Value(context.local()).FromJust());
}


static int trouble_nesting = 0;
static void TroubleCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  trouble_nesting++;

  // Call a JS function that throws an uncaught exception.
  Local<v8::Context> context = args.GetIsolate()->GetCurrentContext();
  Local<v8::Object> arg_this = context->Global();
  Local<Value> trouble_callee =
      (trouble_nesting == 3)
          ? arg_this->Get(context, v8_str("trouble_callee")).ToLocalChecked()
          : arg_this->Get(context, v8_str("trouble_caller")).ToLocalChecked();
  CHECK(trouble_callee->IsFunction());
  args.GetReturnValue().Set(Function::Cast(*trouble_callee)
                                ->Call(context, arg_this, 0, nullptr)
                                .FromMaybe(v8::Local<v8::Value>()));
}


static int report_count = 0;
static void ApiUncaughtExceptionTestListener(v8::Local<v8::Message>,
                                             v8::Local<Value>) {
  report_count++;
}


// Counts uncaught exceptions, but other tests running in parallel
// also have uncaught exceptions.
TEST(ApiUncaughtException) {
  report_count = 0;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->AddMessageListener(ApiUncaughtExceptionTestListener);

  Local<v8::FunctionTemplate> fun =
      v8::FunctionTemplate::New(isolate, TroubleCallback);
  v8::Local<v8::Object> global = env->Global();
  CHECK(global->Set(env.local(), v8_str("trouble"),
                    fun->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  CompileRun(
      "function trouble_callee() {"
      "  var x = null;"
      "  return x.foo;"
      "};"
      "function trouble_caller() {"
      "  trouble();"
      "};");
  Local<Value> trouble =
      global->Get(env.local(), v8_str("trouble")).ToLocalChecked();
  CHECK(trouble->IsFunction());
  Local<Value> trouble_callee =
      global->Get(env.local(), v8_str("trouble_callee")).ToLocalChecked();
  CHECK(trouble_callee->IsFunction());
  Local<Value> trouble_caller =
      global->Get(env.local(), v8_str("trouble_caller")).ToLocalChecked();
  CHECK(trouble_caller->IsFunction());
  Function::Cast(*trouble_caller)
      ->Call(env.local(), global, 0, nullptr)
      .FromMaybe(v8::Local<v8::Value>());
  CHECK_EQ(1, report_count);
  isolate->RemoveMessageListeners(ApiUncaughtExceptionTestListener);
}


static const char* script_resource_name = "ExceptionInNativeScript.js";
static void ExceptionInNativeScriptTestListener(v8::Local<v8::Message> message,
                                                v8::Local<Value>) {
  v8::Isolate* isolate = message->GetIsolate();
  v8::Local<v8::Value> name_val = message->GetScriptOrigin().ResourceName();
  CHECK(!name_val.IsEmpty() && name_val->IsString());
  v8::String::Utf8Value name(isolate,
                             message->GetScriptOrigin().ResourceName());
  CHECK_EQ(0, strcmp(script_resource_name, *name));
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  CHECK_EQ(3, message->GetLineNumber(context).FromJust());
  v8::String::Utf8Value source_line(
      isolate, message->GetSourceLine(context).ToLocalChecked());
  CHECK_EQ(0, strcmp("  new o.foo();", *source_line));
}


TEST(ExceptionInNativeScript) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->AddMessageListener(ExceptionInNativeScriptTestListener);

  Local<v8::FunctionTemplate> fun =
      v8::FunctionTemplate::New(isolate, TroubleCallback);
  v8::Local<v8::Object> global = env->Global();
  CHECK(global->Set(env.local(), v8_str("trouble"),
                    fun->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  CompileRunWithOrigin(
      "function trouble() {\n"
      "  var o = {};\n"
      "  new o.foo();\n"
      "};",
      script_resource_name);
  Local<Value> trouble =
      global->Get(env.local(), v8_str("trouble")).ToLocalChecked();
  CHECK(trouble->IsFunction());
  CHECK(Function::Cast(*trouble)
            ->Call(env.local(), global, 0, nullptr)
            .IsEmpty());
  isolate->RemoveMessageListeners(ExceptionInNativeScriptTestListener);
}


TEST(CompilationErrorUsingTryCatchHandler) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::TryCatch try_catch(env->GetIsolate());
  CHECK(v8_try_compile("This doesn't &*&@#$&*^ compile.").IsEmpty());
  CHECK(*try_catch.Exception());
  CHECK(try_catch.HasCaught());
}

// For use within the TestSecurityHandler() test.
static bool g_security_callback_result = false;
static bool SecurityTestCallback(Local<v8::Context> accessing_context,
                                 Local<v8::Object> accessed_object,
                                 Local<v8::Value> data) {
  printf("a\n");
  CHECK(!data.IsEmpty() && data->IsInt32());
  CHECK_EQ(42, data->Int32Value(accessing_context).FromJust());
  return g_security_callback_result;
}


// SecurityHandler can't be run twice
TEST(SecurityHandler) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope0(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetAccessCheckCallback(SecurityTestCallback, v8_num(42));
  // Create an environment
  v8::Local<Context> context0 = Context::New(isolate, nullptr, global_template);
  context0->Enter();

  v8::Local<v8::Object> global0 = context0->Global();
  v8::Local<Script> script0 = v8_compile("foo = 111");
  script0->Run(context0).ToLocalChecked();
  CHECK(global0->Set(context0, v8_str("0"), v8_num(999)).FromJust());
  v8::Local<Value> foo0 =
      global0->Get(context0, v8_str("foo")).ToLocalChecked();
  CHECK_EQ(111, foo0->Int32Value(context0).FromJust());
  v8::Local<Value> z0 = global0->Get(context0, v8_str("0")).ToLocalChecked();
  CHECK_EQ(999, z0->Int32Value(context0).FromJust());

  // Create another environment, should fail security checks.
  v8::HandleScope scope1(isolate);

  v8::Local<Context> context1 = Context::New(isolate, nullptr, global_template);
  context1->Enter();

  v8::Local<v8::Object> global1 = context1->Global();
  global1->Set(context1, v8_str("othercontext"), global0).FromJust();
  // This set will fail the security check.
  v8::Local<Script> script1 =
      v8_compile("othercontext.foo = 222; othercontext[0] = 888;");
  CHECK(script1->Run(context1).IsEmpty());
  g_security_callback_result = true;
  // This read will pass the security check.
  v8::Local<Value> foo1 =
      global0->Get(context1, v8_str("foo")).ToLocalChecked();
  CHECK_EQ(111, foo1->Int32Value(context0).FromJust());
  // This read will pass the security check.
  v8::Local<Value> z1 = global0->Get(context1, v8_str("0")).ToLocalChecked();
  CHECK_EQ(999, z1->Int32Value(context1).FromJust());

  // Create another environment, should pass security checks.
  {
    v8::HandleScope scope2(isolate);
    LocalContext context2;
    v8::Local<v8::Object> global2 = context2->Global();
    CHECK(global2->Set(context2.local(), v8_str("othercontext"), global0)
              .FromJust());
    v8::Local<Script> script2 =
        v8_compile("othercontext.foo = 333; othercontext[0] = 888;");
    script2->Run(context2.local()).ToLocalChecked();
    v8::Local<Value> foo2 =
        global0->Get(context2.local(), v8_str("foo")).ToLocalChecked();
    CHECK_EQ(333, foo2->Int32Value(context2.local()).FromJust());
    v8::Local<Value> z2 =
        global0->Get(context2.local(), v8_str("0")).ToLocalChecked();
    CHECK_EQ(888, z2->Int32Value(context2.local()).FromJust());
  }

  context1->Exit();
  context0->Exit();
}


THREADED_TEST(SecurityChecks) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);

  // Create a function in env1.
  CompileRun("spy=function(){return spy;}");
  Local<Value> spy =
      env1->Global()->Get(env1.local(), v8_str("spy")).ToLocalChecked();
  CHECK(spy->IsFunction());

  // Create another function accessing global objects.
  CompileRun("spy2=function(){return new this.Array();}");
  Local<Value> spy2 =
      env1->Global()->Get(env1.local(), v8_str("spy2")).ToLocalChecked();
  CHECK(spy2->IsFunction());

  // Switch to env2 in the same domain and invoke spy on env2.
  {
    env2->SetSecurityToken(foo);
    // Enter env2
    Context::Scope scope_env2(env2);
    Local<Value> result = Function::Cast(*spy)
                              ->Call(env2, env2->Global(), 0, nullptr)
                              .ToLocalChecked();
    CHECK(result->IsFunction());
  }

  {
    env2->SetSecurityToken(bar);
    Context::Scope scope_env2(env2);

    // Call cross_domain_call, it should throw an exception
    v8::TryCatch try_catch(env1->GetIsolate());
    CHECK(Function::Cast(*spy2)
              ->Call(env2, env2->Global(), 0, nullptr)
              .IsEmpty());
    CHECK(try_catch.HasCaught());
  }
}


// Regression test case for issue 1183439.
THREADED_TEST(SecurityChecksForPrototypeChain) {
  LocalContext current;
  v8::HandleScope scope(current->GetIsolate());
  v8::Local<Context> other = Context::New(current->GetIsolate());

  // Change context to be able to get to the Object function in the
  // other context without hitting the security checks.
  v8::Local<Value> other_object;
  {
    Context::Scope context_scope(other);
    other_object =
        other->Global()->Get(other, v8_str("Object")).ToLocalChecked();
    CHECK(other->Global()->Set(other, v8_num(42), v8_num(87)).FromJust());
  }

  CHECK(current->Global()
            ->Set(current.local(), v8_str("other"), other->Global())
            .FromJust());
  CHECK(v8_compile("other")
            ->Run(current.local())
            .ToLocalChecked()
            ->Equals(current.local(), other->Global())
            .FromJust());

  // Make sure the security check fails here and we get an undefined
  // result instead of getting the Object function. Repeat in a loop
  // to make sure to exercise the IC code.
  v8::Local<Script> access_other0 = v8_compile("other.Object");
  v8::Local<Script> access_other1 = v8_compile("other[42]");
  for (int i = 0; i < 5; i++) {
    CHECK(access_other0->Run(current.local()).IsEmpty());
    CHECK(access_other1->Run(current.local()).IsEmpty());
  }

  // Create an object that has 'other' in its prototype chain and make
  // sure we cannot access the Object function indirectly through
  // that. Repeat in a loop to make sure to exercise the IC code.
  v8_compile(
      "function F() { };"
      "F.prototype = other;"
      "var f = new F();")
      ->Run(current.local())
      .ToLocalChecked();
  v8::Local<Script> access_f0 = v8_compile("f.Object");
  v8::Local<Script> access_f1 = v8_compile("f[42]");
  for (int j = 0; j < 5; j++) {
    CHECK(access_f0->Run(current.local()).IsEmpty());
    CHECK(access_f1->Run(current.local()).IsEmpty());
  }

  // Now it gets hairy: Set the prototype for the other global object
  // to be the current global object. The prototype chain for 'f' now
  // goes through 'other' but ends up in the current global object.
  {
    Context::Scope context_scope(other);
    CHECK(other->Global()
              ->Set(other, v8_str("__proto__"), current->Global())
              .FromJust());
  }
  // Set a named and an index property on the current global
  // object. To force the lookup to go through the other global object,
  // the properties must not exist in the other global object.
  CHECK(current->Global()
            ->Set(current.local(), v8_str("foo"), v8_num(100))
            .FromJust());
  CHECK(current->Global()
            ->Set(current.local(), v8_num(99), v8_num(101))
            .FromJust());
  // Try to read the properties from f and make sure that the access
  // gets stopped by the security checks on the other global object.
  Local<Script> access_f2 = v8_compile("f.foo");
  Local<Script> access_f3 = v8_compile("f[99]");
  for (int k = 0; k < 5; k++) {
    CHECK(access_f2->Run(current.local()).IsEmpty());
    CHECK(access_f3->Run(current.local()).IsEmpty());
  }
}


static bool security_check_with_gc_called;

static bool SecurityTestCallbackWithGC(Local<v8::Context> accessing_context,
                                       Local<v8::Object> accessed_object,
                                       Local<v8::Value> data) {
  i::heap::InvokeMajorGC(CcTest::heap());
  security_check_with_gc_called = true;
  return true;
}


TEST(SecurityTestGCAllowed) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetAccessCheckCallback(SecurityTestCallbackWithGC);

  v8::Local<Context> context = Context::New(isolate);
  v8::Context::Scope context_scope(context);

  CHECK(context->Global()
            ->Set(context, v8_str("obj"),
                  object_template->NewInstance(context).ToLocalChecked())
            .FromJust());

  security_check_with_gc_called = false;
  CompileRun("obj[0] = new String(1002);");
  CHECK(security_check_with_gc_called);

  security_check_with_gc_called = false;
  CHECK(CompileRun("obj[0]")
            ->ToString(context)
            .ToLocalChecked()
            ->Equals(context, v8_str("1002"))
            .FromJust());
  CHECK(security_check_with_gc_called);
}


THREADED_TEST(CrossDomainDelete) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(
      env1->Global()->Set(env1.local(), v8_str("prop"), v8_num(3)).FromJust());
  CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());

  // Change env2 to a different domain and delete env1.prop.
  env2->SetSecurityToken(bar);
  {
    Context::Scope scope_env2(env2);
    Local<Value> result =
        CompileRun("delete env1.prop");
    CHECK(result.IsEmpty());
  }

  // Check that env1.prop still exists.
  Local<Value> v =
      env1->Global()->Get(env1.local(), v8_str("prop")).ToLocalChecked();
  CHECK(v->IsNumber());
  CHECK_EQ(3, v->Int32Value(env1.local()).FromJust());
}


THREADED_TEST(CrossDomainPropertyIsEnumerable) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(
      env1->Global()->Set(env1.local(), v8_str("prop"), v8_num(3)).FromJust());
  CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());

  // env1.prop is enumerable in env2.
  Local<String> test = v8_str("propertyIsEnumerable.call(env1, 'prop')");
  {
    Context::Scope scope_env2(env2);
    Local<Value> result = CompileRun(test);
    CHECK(result->IsTrue());
  }

  // Change env2 to a different domain and test again.
  env2->SetSecurityToken(bar);
  {
    Context::Scope scope_env2(env2);
    Local<Value> result = CompileRun(test);
    CHECK(result.IsEmpty());
  }
}


THREADED_TEST(CrossDomainFor) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(
      env1->Global()->Set(env1.local(), v8_str("prop"), v8_num(3)).FromJust());
  CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());

  // Change env2 to a different domain and set env1's global object
  // as the __proto__ of an object in env2 and enumerate properties
  // in for-in. It shouldn't enumerate properties on env1's global
  // object. It shouldn't throw either, just silently ignore them.
  env2->SetSecurityToken(bar);
  {
    Context::Scope scope_env2(env2);
    Local<Value> result = CompileRun(
        "(function() {"
        "  try {"
        "    for (var p in env1) {"
        "      if (p == 'prop') return false;"
        "    }"
        "    return true;"
        "  } catch (e) {"
        "    return false;"
        "  }"
        "})()");
    CHECK(result->IsTrue());
  }
}


THREADED_TEST(CrossDomainForInOnPrototype) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(
      env1->Global()->Set(env1.local(), v8_str("prop"), v8_num(3)).FromJust());
  CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());

  // Change env2 to a different domain and set env1's global object
  // as the __proto__ of an object in env2 and enumerate properties
  // in for-in. It shouldn't enumerate properties on env1's global
  // object.
  env2->SetSecurityToken(bar);
  {
    Context::Scope scope_env2(env2);
    Local<Value> result = CompileRun(
        "(function() {"
        "  var obj = { '__proto__': env1 };"
        "  try {"
        "    for (var p in obj) {"
        "      if (p == 'prop') return false;"
        "    }"
        "    return true;"
        "  } catch (e) {"
        "    return false;"
        "  }"
        "})()");
    CHECK(result->IsTrue());
  }
}


TEST(ContextDetachGlobal) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());


  Local<Value> foo = v8_str("foo");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  // Enter env2
  env2->Enter();

  // Create a function in env2 and add a reference to it in env1.
  Local<v8::Object> global2 = env2->Global();
  CHECK(global2->Set(env2, v8_str("prop"),
                     v8::Integer::New(env2->GetIsolate(), 1))
            .FromJust());
  CompileRun("function getProp() {return prop;}");

  CHECK(env1->Global()
            ->Set(env1.local(), v8_str("getProp"),
                  global2->Get(env2, v8_str("getProp")).ToLocalChecked())
            .FromJust());

  // Detach env2's global, and reuse the global object of env2
  env2->Exit();
  env2->DetachGlobal();

  v8::Local<Context> env3 = Context::New(
      env1->GetIsolate(), nullptr, v8::Local<v8::ObjectTemplate>(), global2);
  env3->SetSecurityToken(v8_str("bar"));

  env3->Enter();
  Local<v8::Object> global3 = env3->Global();
  CHECK(global2->Equals(env3, global3).FromJust());
  CHECK(global3->Get(env3, v8_str("prop")).ToLocalChecked()->IsUndefined());
  CHECK(global3->Get(env3, v8_str("getProp")).ToLocalChecked()->IsUndefined());
  CHECK(global3->Set(env3, v8_str("prop"),
                     v8::Integer::New(env3->GetIsolate(), -1))
            .FromJust());
  CHECK(global3->Set(env3, v8_str("prop2"),
                     v8::Integer::New(env3->GetIsolate(), 2))
            .FromJust());
  env3->Exit();

  // Call getProp in env1, and it should return the value 1
  {
    Local<v8::Object> global1 = env1->Global();
    Local<Value> get_prop =
        global1->Get(env1.local(), v8_str("getProp")).ToLocalChecked();
    CHECK(get_prop->IsFunction());
    v8::TryCatch try_catch(env1->GetIsolate());
    Local<Value> r = Function::Cast(*get_prop)
                         ->Call(env1.local(), global1, 0, nullptr)
                         .ToLocalChecked();
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(1, r->Int32Value(env1.local()).FromJust());
  }

  // Check that env3 is not accessible from env1
  {
    v8::MaybeLocal<Value> r = global3->Get(env1.local(), v8_str("prop2"));
    CHECK(r.IsEmpty());
  }
}


TEST(DetachGlobal) {
  LocalContext env1;
  v8::HandleScope scope(env1->GetIsolate());

  // Create second environment.
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");

  // Set same security token for env1 and env2.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  // Create a property on the global object in env2.
  {
    v8::Context::Scope context_scope(env2);
    CHECK(env2->Global()
              ->Set(env2, v8_str("p"), v8::Integer::New(env2->GetIsolate(), 42))
              .FromJust());
  }

  // Create a reference to env2 global from env1 global.
  CHECK(env1->Global()
            ->Set(env1.local(), v8_str("other"), env2->Global())
            .FromJust());

  // Check that we have access to other.p in env2 from env1.
  Local<Value> result = CompileRun("other.p");
  CHECK(result->IsInt32());
  CHECK_EQ(42, result->Int32Value(env1.local()).FromJust());

  // Hold on to global from env2 and detach global from env2.
  Local<v8::Object> global2 = env2->Global();
  env2->DetachGlobal();

  // Check that the global has been detached. No other.p property can
  // be found.
  result = CompileRun("other.p");
  CHECK(result.IsEmpty());

  // Reuse global2 for env3.
  v8::Local<Context> env3 = Context::New(
      env1->GetIsolate(), nullptr, v8::Local<v8::ObjectTemplate>(), global2);
  CHECK(global2->Equals(env1.local(), env3->Global()).FromJust());

  // Start by using the same security token for env3 as for env1 and env2.
  env3->SetSecurityToken(foo);

  // Create a property on the global object in env3.
  {
    v8::Context::Scope context_scope(env3);
    CHECK(env3->Global()
              ->Set(env3, v8_str("p"), v8::Integer::New(env3->GetIsolate(), 24)
```