Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name `test-api.cc` strongly suggests that this code tests the V8 JavaScript engine's C++ API. Each `THREADED_TEST` or `TEST` likely focuses on a specific aspect of this API.

2. **Analyze Individual Tests:** Go through each test function and determine its objective. Look for V8 API calls and assertions (`CHECK`, `CHECK_EQ`).

   * **`TryCatchSourceInfo`:**  This test compiles and runs JavaScript code within a `try...catch` block and verifies the source information (resource name, line number) associated with the script.
   * **`TryCatchSourceInfoForEOSError`:**  Similar to the previous test, but focuses on error handling during compilation. It checks the line number and column of the error.
   * **`CompilationCache`:** This test compiles the same source code multiple times (with the same and different origins) and runs it, suggesting it's verifying the compilation caching mechanism.
   * **`CallbackFunctionName`:** This test creates a JavaScript object with a function property and then checks if the `name` property of that function is correctly set.
   * **`DateAccess`:** This test creates a `Date` object and verifies its value.
   * **`PropertyEnumeration` and `PropertyEnumeration2`:** These tests explore how object properties are enumerated, including inherited properties and properties of arrays and plain objects. They use `GetPropertyNames` and `GetOwnPropertyNames`.
   * **`GetPropertyNames`:** This test extensively checks the `GetPropertyNames` method with various options for including/excluding prototypes, symbols, and indices.
   * **`ProxyGetPropertyNames` and `ProxyGetPropertyNamesWithOwnKeysTrap`:** These tests are similar to `GetPropertyNames` but involve JavaScript Proxies and their influence on property enumeration.
   * **`AccessChecksReenabledCorrectly`:** This test deals with access checks on object properties, potentially after optimizations or map changes.
   * **`DictionaryICLoadedFunction`:** This test focuses on ensuring that inline caches for dictionary-mode objects correctly handle functions that might not be fully compiled yet. It specifically targets `LoadIC` and `CallIC`.
   * **`CrossContextNew`:** This test examines how `new` calls behave when a constructor from one V8 Context is called from another.
   * **`ObjectClone`:**  This test verifies the `Clone()` method of V8 objects, ensuring that cloned objects are independent.
   * **`MorphCompositeStringTest`:** This test deals with string manipulation and flattening, specifically when the underlying string components change their internal representation (e.g., from one-byte to two-byte).

3. **Identify JavaScript Relevance and Provide Examples:**  For tests related to JavaScript behavior, provide corresponding JavaScript examples.

   * `TryCatchSourceInfo`: Demonstrating `try...catch` and how errors provide line numbers.
   * `CallbackFunctionName`:  Showing how to access the `name` property of a function.
   * `PropertyEnumeration`, `GetPropertyNames`, `ProxyGetPropertyNames`: Examples of iterating over object properties using `for...in` and `Object.keys()`.
   * `CrossContextNew`:  Showing how `new` works across different JavaScript realms (though this is more of a V8 API concept).

4. **Look for Logic and Potential Errors:** Analyze tests that involve more complex object manipulation or API interactions for potential logic and common errors.

   * `PropertyEnumeration`:  Highlight the difference between own properties and inherited properties. A common error is assuming `for...in` only iterates over own properties.
   * `GetPropertyNames` and `ProxyGetPropertyNames`:  The different filters and modes can be confusing. A common error is not understanding how these options affect the returned property list.

5. **Check for `.tq` Suffix:** None of the provided code looks like Torque (it's standard C++ using the V8 API).

6. **Address Input/Output and Assumptions:** For tests with clear logic, formulate hypothetical inputs and expected outputs. The property enumeration tests are good examples.

7. **Synthesize the Summary:** Combine the observations about each test into a concise summary of the file's functionality. Emphasize that it's a test file for the V8 API.

8. **Consider the "Part X of Y" Information:** Acknowledge that this is part 17 of 36, implying this file covers a subset of the API testing.

**Self-Correction/Refinement:**

* Initially, one might focus too much on the low-level C++ details. The goal is to explain the *functionality* being tested, which is related to JavaScript behavior. Shift the focus to the JavaScript concepts.
* Ensure the JavaScript examples are clear and directly related to the C++ test.
* Double-check the assumptions and inputs/outputs for logical consistency.
* Make sure the summary accurately reflects the range of topics covered in the provided snippet.
好的，让我们分析一下 `v8/test/cctest/test-api.cc` 的这个代码片段。

**功能列表:**

这个代码片段主要包含了一系列的单元测试，用于测试 V8 JavaScript 引擎的 C++ API 的各种功能。 具体来说，它测试了以下方面：

1. **异常处理和源码信息 (`TryCatchSourceInfo`, `TryCatchSourceInfoForEOSError`):**
   - 测试在 `try...catch` 块中编译和运行 JavaScript 代码时，V8 能否正确地报告错误发生的源码位置（资源名称、行号）。
   - 特别测试了当编译发生错误时，能否获取到正确的行号和列号信息。

2. **编译缓存 (`CompilationCache`):**
   - 测试 V8 的编译缓存机制，验证对于相同的源代码，即使来源 (`origin`) 不同，也能正确执行。

3. **回调函数名 (`CallbackFunctionName`):**
   - 测试通过 C++ API 创建的函数对象，其 `name` 属性是否能正确反映 C++ 中设置的名称。

4. **Date 对象访问 (`DateAccess`):**
   - 测试创建和访问 `Date` 对象的功能，验证其值是否正确。

5. **属性枚举 (`PropertyEnumeration`, `PropertyEnumeration2`, `GetPropertyNames`, `ProxyGetPropertyNames`, `ProxyGetPropertyNamesWithOwnKeysTrap`):**
   - 测试 V8 如何枚举对象的属性，包括自有属性和继承属性。
   - 测试了不同类型的对象（普通对象、数组、包含 Symbol 属性的对象、使用 `Object.create(null)` 创建的对象）的属性枚举行为。
   - 详细测试了 `GetPropertyNames` 方法的不同选项，例如是否包含原型链上的属性、是否包含 Symbol 属性、是否包含索引属性等。
   - 测试了 `Proxy` 对象对属性枚举的影响，包括使用自定义 `ownKeys` trap 的情况。

6. **访问检查 (`AccessChecksReenabledCorrectly`):**
   - 测试在设置访问检查回调函数后，访问控制是否能正确生效，以及在对象结构发生变化后（例如添加大量属性导致 map 复制），访问控制是否仍然有效。

7. **字典模式下加载未编译函数 (`DictionaryICLoadedFunction`):**
   - 测试当对象以字典模式存储属性时，在加载或调用属性值（如果该值是一个尚未编译的函数）时，V8 是否能正确处理，避免潜在的跨上下文代码共享问题。

8. **跨上下文调用构造函数 (`CrossContextNew`):**
   - 测试在一个上下文中定义的构造函数，在另一个上下文中通过 `new` 关键字调用时，新创建的对象是否属于定义构造函数的上下文。

9. **对象克隆 (`ObjectClone`):**
   - 测试 V8 对象的 `Clone()` 方法，验证克隆后的对象与原对象拥有相同的属性和值，并且修改克隆对象的属性不会影响原对象。

10. **字符串变形 (`MorphCompositeStringTest`):**
    - 测试当字符串的内部表示形式发生变化时（例如从单字节字符串变为双字节字符串），V8 是否仍然可以正确地进行字符串拼接和展平操作。

**关于文件后缀和 Torque：**

根据描述，如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾，那么它才是 V8 Torque 源代码。由于给出的文件路径是 `.cc`，所以它是一个 C++ 源代码文件，而不是 Torque 文件。

**与 JavaScript 功能的关系和示例：**

这个文件中的测试案例直接关联着许多 JavaScript 的核心功能。以下是一些与 JavaScript 功能相关的测试及其对应的 JavaScript 例子：

1. **异常处理:**

   ```javascript
   try {
     function Baz() {
       throw 'nirk';
     }
     function Bar() {
       return Baz();
     }
     function Foo() {
       return Bar();
     }
     Foo();
   } catch (e) {
     console.error("Caught an error:", e); // 这里的 e 就是 'nirk'
   }
   ```

2. **函数名:**

   ```javascript
   const obj = {
     asdf: function() { return 42; }
   };
   console.log(obj.asdf.name); // 输出 "asdf"
   ```

3. **Date 对象:**

   ```javascript
   const date = new Date(1224744689038);
   console.log(date.valueOf()); // 输出 1224744689038
   ```

4. **属性枚举:**

   ```javascript
   const obj = { a: 1, b: 2 };
   const arr = [1, 2, 3];
   const proto = { x: 1, y: 2, z: 3 };
   const objWithProto = { __proto__: proto, w: 0, z: 1 };
   const objNullProto = Object.create(null);
   objNullProto.a = 1;
   objNullProto[12345678] = 1;

   console.log("Properties of obj:");
   for (let key in obj) {
     console.log(key); // 输出 "a", "b"
   }

   console.log("Own properties of obj:");
   console.log(Object.keys(obj)); // 输出 ["a", "b"]

   console.log("Properties of arr:");
   for (let key in arr) {
     console.log(key); // 输出 "0", "1", "2"
   }

   console.log("Properties of objWithProto:");
   for (let key in objWithProto) {
     console.log(key); // 输出 "w", "z", "x", "y"
   }

   console.log("Own properties of objWithProto:");
   console.log(Object.keys(objWithProto)); // 输出 ["w", "z"]

   console.log("Properties of objNullProto:");
   for (let key in objNullProto) {
     console.log(key); // 输出 "a", "12345678"
   }
   console.log(Object.keys(objNullProto)); // 输出 ["a", "12345678"]
   ```

5. **Proxy 对象和属性枚举:**

   ```javascript
   const target = { a: 1, b: 2 };
   const proxy = new Proxy(target, {});
   for (let key in proxy) {
     console.log(key); // 输出 "a", "b"
   }

   const proxyWithOwnKeys = new Proxy(target, {
     ownKeys(target) {
       return Reflect.ownKeys(target);
     }
   });
   for (let key in proxyWithOwnKeys) {
     console.log(key); // 输出 "a", "b"
   }
   ```

6. **跨上下文 `new` 调用 (概念上，JavaScript 本身没有显式的上下文概念，但在 V8 内部有):**

   这涉及到 V8 的隔离概念，在 JavaScript 中不直接体现，但在 V8 API 中有明确的上下文 (Isolate/Context)。

7. **对象克隆:**

   JavaScript 并没有直接提供 `object.clone()` 方法，但可以通过一些方式实现浅拷贝或深拷贝：

   ```javascript
   const obj = { alpha: 'hello', beta: 123 };
   const clone = { ...obj }; // 浅拷贝
   clone.beta = 456;
   console.log(obj.beta);   // 输出 123
   console.log(clone.beta); // 输出 456
   ```

**代码逻辑推理和假设输入输出：**

以 `TryCatchSourceInfo` 测试为例：

**假设输入:**
- `source`: 一段包含函数调用链并抛出异常的 JavaScript 代码字符串。
- `resource_name`: 字符串 "test.js"。

**预期输出:**
- `script`: 成功编译的 JavaScript 脚本对象。
- `CheckTryCatchSourceInfo` 函数会验证当脚本执行抛出异常时，V8 内部记录的异常信息（例如通过 `try...catch` 捕获）能够正确关联到 `resource_name` 和行号 0。

对于 `PropertyEnumeration` 测试，输入是执行一段 JavaScript 代码创建的包含不同类型对象的数组。输出是针对数组中每个对象，使用 V8 API 检查其可枚举的属性名称，并与预期的属性名称列表进行比较。

**用户常见的编程错误：**

1. **混淆自有属性和继承属性：**  用户可能期望使用 `for...in` 循环只遍历对象自身的属性，但实际上它会遍历到原型链上的可枚举属性。`Object.keys()` 和 `Object.hasOwnProperty()` 可以用来区分自有属性。

   ```javascript
   const proto = { x: 1 };
   const obj = Object.create(proto);
   obj.y = 2;

   for (let key in obj) {
     console.log(key); // 错误地认为只会输出 "y"
   }

   console.log(Object.keys(obj)); // 正确获取自有属性: ["y"]
   ```

2. **不了解属性枚举的顺序：**  对于普通对象，属性枚举的顺序是不确定的。对于数组，会按照索引顺序枚举。依赖于枚举顺序可能导致问题。

3. **对 Proxy 的 `ownKeys` trap 理解不足：**  自定义 `ownKeys` trap 会影响 `Object.keys()`、`for...in` 等操作的结果，如果不理解其行为，可能会导致意外的属性枚举结果。

**功能归纳 (作为第 17 部分):**

作为 36 个部分中的第 17 部分，这个代码片段主要关注于 **V8 C++ API 中与脚本编译、异常处理、对象属性操作（包括枚举和访问控制）、跨上下文交互以及对象生命周期管理相关的测试**。它深入测试了 V8 引擎在处理不同类型的 JavaScript 代码和对象时的行为，确保 API 的正确性和稳定性。  考虑到它是测试套件的一部分，可以推断之前的部分可能涉及更基础的 API 测试，而后续的部分可能会涵盖更高级或特定的功能。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第17部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
= context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> source = v8_str(
      "function Foo() {\n"
      "  return Bar();\n"
      "}\n"
      "\n"
      "function Bar() {\n"
      "  return Baz();\n"
      "}\n"
      "\n"
      "function Baz() {\n"
      "  throw 'nirk';\n"
      "}\n"
      "\n"
      "Foo();\n");

  const char* resource_name;
  v8::Local<v8::Script> script;
  resource_name = "test.js";
  script = CompileWithOrigin(source, resource_name, false);
  CheckTryCatchSourceInfo(script, resource_name, 0);

  resource_name = "test1.js";
  v8::ScriptOrigin origin1(v8_str(resource_name), 0, 0);
  script =
      v8::Script::Compile(context.local(), source, &origin1).ToLocalChecked();
  CheckTryCatchSourceInfo(script, resource_name, 0);

  resource_name = "test2.js";
  v8::ScriptOrigin origin2(v8_str(resource_name), 7, 0);
  script =
      v8::Script::Compile(context.local(), source, &origin2).ToLocalChecked();
  CheckTryCatchSourceInfo(script, resource_name, 7);
}


THREADED_TEST(TryCatchSourceInfoForEOSError) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::TryCatch try_catch(context->GetIsolate());
  CHECK(v8::Script::Compile(context.local(), v8_str("!\n")).IsEmpty());
  CHECK(try_catch.HasCaught());
  v8::Local<v8::Message> message = try_catch.Message();
  CHECK_EQ(2, message->GetLineNumber(context.local()).FromJust());
  CHECK_EQ(0, message->GetStartColumn(context.local()).FromJust());
}


THREADED_TEST(CompilationCache) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<v8::String> source0 = v8_str("1234");
  v8::Local<v8::String> source1 = v8_str("1234");
  v8::Local<v8::Script> script0 = CompileWithOrigin(source0, "test.js", false);
  v8::Local<v8::Script> script1 = CompileWithOrigin(source1, "test.js", false);
  v8::Local<v8::Script> script2 = v8::Script::Compile(context.local(), source0)
                                      .ToLocalChecked();  // different origin
  CHECK_EQ(1234, script0->Run(context.local())
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
  CHECK_EQ(1234, script1->Run(context.local())
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
  CHECK_EQ(1234, script2->Run(context.local())
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
}


static void FunctionNameCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(v8_num(42));
}


THREADED_TEST(CallbackFunctionName) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> t = ObjectTemplate::New(isolate);
  t->Set(isolate, "asdf",
         v8::FunctionTemplate::New(isolate, FunctionNameCallback));
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  t->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  v8::Local<v8::Value> value = CompileRun("obj.asdf.name");
  CHECK(value->IsString());
  v8::String::Utf8Value name(isolate, value);
  CHECK_EQ(0, strcmp("asdf", *name));
}


THREADED_TEST(DateAccess) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<v8::Value> date =
      v8::Date::New(context.local(), 1224744689038.0).ToLocalChecked();
  CHECK(date->IsDate());
  CHECK_EQ(1224744689038.0, date.As<v8::Date>()->ValueOf());
}

void CheckIsSymbolAt(v8::Isolate* isolate, v8::Local<v8::Array> properties,
                     unsigned index, const char* name) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Value> value =
      properties->Get(context, v8::Integer::New(isolate, index))
          .ToLocalChecked();
  CHECK(value->IsSymbol());
  v8::String::Utf8Value symbol_name(
      isolate, Local<Symbol>::Cast(value)->Description(isolate));
  if (strcmp(name, *symbol_name) != 0) {
    GRACEFUL_FATAL("properties[%u] was Symbol('%s') instead of Symbol('%s').",
                   index, name, *symbol_name);
  }
}

void CheckStringArray(v8::Isolate* isolate, v8::Local<v8::Array> properties,
                      unsigned length, const char* names[]) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  CHECK_EQ(length, properties->Length());
  for (unsigned i = 0; i < length; i++) {
    v8::Local<v8::Value> value =
        properties->Get(context, v8::Integer::New(isolate, i)).ToLocalChecked();
    if (names[i] == nullptr) {
      DCHECK(value->IsSymbol());
    } else {
      v8::String::Utf8Value elm(isolate, value);
      if (strcmp(names[i], *elm) != 0) {
        GRACEFUL_FATAL("properties[%u] was '%s' instead of '%s'.", i, *elm,
                       names[i]);
      }
    }
  }
}

void CheckProperties(v8::Isolate* isolate, v8::Local<v8::Value> val,
                     unsigned length, const char* names[]) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> obj = val.As<v8::Object>();
  v8::Local<v8::Array> props = obj->GetPropertyNames(context).ToLocalChecked();
  CheckStringArray(isolate, props, length, names);
}


void CheckOwnProperties(v8::Isolate* isolate, v8::Local<v8::Value> val,
                        unsigned elmc, const char* elmv[]) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> obj = val.As<v8::Object>();
  v8::Local<v8::Array> props =
      obj->GetOwnPropertyNames(context).ToLocalChecked();
  CHECK_EQ(elmc, props->Length());
  for (unsigned i = 0; i < elmc; i++) {
    v8::String::Utf8Value elm(
        isolate,
        props->Get(context, v8::Integer::New(isolate, i)).ToLocalChecked());
    CHECK_EQ(0, strcmp(elmv[i], *elm));
  }
}


THREADED_TEST(PropertyEnumeration) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> obj = CompileRun(
      "var result = [];"
      "result[0] = {};"
      "result[1] = {a: 1, b: 2};"
      "result[2] = [1, 2, 3];"
      "var proto = {x: 1, y: 2, z: 3};"
      "var x = { __proto__: proto, w: 0, z: 1 };"
      "result[3] = x;"
      "result[4] = {21350:1};"
      "x = Object.create(null);"
      "x.a = 1; x[12345678] = 1;"
      "result[5] = x;"
      "result;");
  v8::Local<v8::Array> elms = obj.As<v8::Array>();
  CHECK_EQ(6u, elms->Length());
  int elmc0 = 0;
  const char** elmv0 = nullptr;
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 0)).ToLocalChecked(),
      elmc0, elmv0);
  CheckOwnProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 0)).ToLocalChecked(),
      elmc0, elmv0);
  int elmc1 = 2;
  const char* elmv1[] = {"a", "b"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 1)).ToLocalChecked(),
      elmc1, elmv1);
  CheckOwnProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 1)).ToLocalChecked(),
      elmc1, elmv1);
  int elmc2 = 3;
  const char* elmv2[] = {"0", "1", "2"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 2)).ToLocalChecked(),
      elmc2, elmv2);
  CheckOwnProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 2)).ToLocalChecked(),
      elmc2, elmv2);
  int elmc3 = 4;
  const char* elmv3[] = {"w", "z", "x", "y"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 3)).ToLocalChecked(),
      elmc3, elmv3);
  int elmc4 = 2;
  const char* elmv4[] = {"w", "z"};
  CheckOwnProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 3)).ToLocalChecked(),
      elmc4, elmv4);
  // Dictionary elements.
  int elmc5 = 1;
  const char* elmv5[] = {"21350"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 4)).ToLocalChecked(),
      elmc5, elmv5);
  // Dictionary properties.
  int elmc6 = 2;
  const char* elmv6[] = {"12345678", "a"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 5)).ToLocalChecked(),
      elmc6, elmv6);
}


THREADED_TEST(PropertyEnumeration2) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> obj = CompileRun(
      "var result = [];"
      "result[0] = {};"
      "result[1] = {a: 1, b: 2};"
      "result[2] = [1, 2, 3];"
      "var proto = {x: 1, y: 2, z: 3};"
      "var x = { __proto__: proto, w: 0, z: 1 };"
      "result[3] = x;"
      "result;");
  v8::Local<v8::Array> elms = obj.As<v8::Array>();
  CHECK_EQ(4u, elms->Length());
  int elmc0 = 0;
  const char** elmv0 = nullptr;
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 0)).ToLocalChecked(),
      elmc0, elmv0);

  v8::Local<v8::Value> val =
      elms->Get(context.local(), v8::Integer::New(isolate, 0)).ToLocalChecked();
  v8::Local<v8::Array> props =
      val.As<v8::Object>()->GetPropertyNames(context.local()).ToLocalChecked();
  CHECK_EQ(0u, props->Length());
  for (uint32_t i = 0; i < props->Length(); i++) {
    printf("p[%u]\n", i);
  }
}

THREADED_TEST(GetPropertyNames) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "var result = {0: 0, 1: 1, a: 2, b: 3};"
      "result[2**32] = '4294967296';"
      "result[2**32-1] = '4294967295';"
      "result[2**32-2] = '4294967294';"
      "result[Symbol('symbol')] = true;"
      "result.__proto__ = {__proto__:null, 2: 4, 3: 5, c: 6, d: 7};"
      "result;");
  v8::Local<v8::Object> object = result.As<v8::Object>();
  v8::PropertyFilter default_filter =
      static_cast<v8::PropertyFilter>(v8::ONLY_ENUMERABLE | v8::SKIP_SYMBOLS);
  v8::PropertyFilter include_symbols_filter = v8::ONLY_ENUMERABLE;

  v8::Local<v8::Array> properties =
      object->GetPropertyNames(context.local()).ToLocalChecked();
  const char* expected_properties1[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295", "2",
                                        "3", "c",          "d"};
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties1_1[] = {
      "0",          "1",     "4294967294", "a", "b", "4294967296",
      "4294967295", nullptr, "2",          "3", "c", "d"};
  CheckStringArray(isolate, properties, 12, expected_properties1_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties2[] = {"a",          "b", "4294967296",
                                        "4294967295", "c", "d"};
  CheckStringArray(isolate, properties, 6, expected_properties2);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties2_1[] = {
      "a", "b", "4294967296", "4294967295", nullptr, "c", "d"};
  CheckStringArray(isolate, properties, 7, expected_properties2_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  const char* expected_properties3[] = {
      "0", "1", "4294967294", "a", "b", "4294967296", "4294967295",
  };
  CheckStringArray(isolate, properties, 7, expected_properties3);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties3_1[] = {
      "0", "1", "4294967294", "a", "b", "4294967296", "4294967295", nullptr};
  CheckStringArray(isolate, properties, 8, expected_properties3_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties4[] = {"a", "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 4, expected_properties4);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties4_1[] = {"a", "b", "4294967296", "4294967295",
                                          nullptr};
  CheckStringArray(isolate, properties, 5, expected_properties4_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");
}

THREADED_TEST(ProxyGetPropertyNames) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "var target = {0: 0, 1: 1, a: 2, b: 3};"
      "target[2**32] = '4294967296';"
      "target[2**32-1] = '4294967295';"
      "target[2**32-2] = '4294967294';"
      "target[Symbol('symbol')] = true;"
      "target.__proto__ = {__proto__:null, 2: 4, 3: 5, c: 6, d: 7};"
      "var result = new Proxy(target, {});"
      "result;");
  v8::Local<v8::Object> object = result.As<v8::Object>();
  v8::PropertyFilter default_filter =
      static_cast<v8::PropertyFilter>(v8::ONLY_ENUMERABLE | v8::SKIP_SYMBOLS);
  v8::PropertyFilter include_symbols_filter = v8::ONLY_ENUMERABLE;

  v8::Local<v8::Array> properties =
      object->GetPropertyNames(context.local()).ToLocalChecked();
  const char* expected_properties1[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295", "2",
                                        "3", "c",          "d"};
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties1_1[] = {
      "0",          "1",     "4294967294", "a", "b", "4294967296",
      "4294967295", nullptr, "2",          "3", "c", "d"};
  CheckStringArray(isolate, properties, 12, expected_properties1_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties2[] = {"a",          "b", "4294967296",
                                        "4294967295", "c", "d"};
  CheckStringArray(isolate, properties, 6, expected_properties2);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties2_1[] = {
      "a", "b", "4294967296", "4294967295", nullptr, "c", "d"};
  CheckStringArray(isolate, properties, 7, expected_properties2_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  const char* expected_properties3[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 7, expected_properties3);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties3_1[] = {
      "0", "1", "4294967294", "a", "b", "4294967296", "4294967295", nullptr};
  CheckStringArray(isolate, properties, 8, expected_properties3_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties4[] = {"a", "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 4, expected_properties4);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties4_1[] = {"a", "b", "4294967296", "4294967295",
                                          nullptr};
  CheckStringArray(isolate, properties, 5, expected_properties4_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");
}

THREADED_TEST(ProxyGetPropertyNamesWithOwnKeysTrap) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "var target = {0: 0, 1: 1, a: 2, b: 3};"
      "target[2**32] = '4294967296';"
      "target[2**32-1] = '4294967295';"
      "target[2**32-2] = '4294967294';"
      "target[Symbol('symbol')] = true;"
      "target.__proto__ = {__proto__:null, 2: 4, 3: 5, c: 6, d: 7};"
      "var result = new Proxy(target, { ownKeys: (t) => Reflect.ownKeys(t) });"
      "result;");
  v8::Local<v8::Object> object = result.As<v8::Object>();
  v8::PropertyFilter default_filter =
      static_cast<v8::PropertyFilter>(v8::ONLY_ENUMERABLE | v8::SKIP_SYMBOLS);
  v8::PropertyFilter include_symbols_filter = v8::ONLY_ENUMERABLE;

  v8::Local<v8::Array> properties =
      object->GetPropertyNames(context.local()).ToLocalChecked();
  const char* expected_properties1[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295", "2",
                                        "3", "c",          "d"};
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties1_1[] = {
      "0",          "1",     "4294967294", "a", "b", "4294967296",
      "4294967295", nullptr, "2",          "3", "c", "d"};
  CheckStringArray(isolate, properties, 12, expected_properties1_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties2[] = {"a",          "b", "4294967296",
                                        "4294967295", "c", "d"};
  CheckStringArray(isolate, properties, 6, expected_properties2);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties2_1[] = {
      "a", "b", "4294967296", "4294967295", nullptr, "c", "d"};
  CheckStringArray(isolate, properties, 7, expected_properties2_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  const char* expected_properties3[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 7, expected_properties3);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties3_1[] = {
      "0", "1", "4294967294", "a", "b", "4294967296", "4294967295", nullptr};
  CheckStringArray(isolate, properties, 8, expected_properties3_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties4[] = {"a", "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 4, expected_properties4);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties4_1[] = {"a", "b", "4294967296", "4294967295",
                                          nullptr};
  CheckStringArray(isolate, properties, 5, expected_properties4_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");
}

THREADED_TEST(AccessChecksReenabledCorrectly) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessAlwaysBlocked);
  templ->Set(isolate, "a", v8_str("a"));
  // Add more than 8 (see kMaxFastProperties) properties
  // so that the constructor will force copying map.
  // Cannot sprintf, gcc complains unsafety.
  char buf[4];
  for (char i = '0'; i <= '9' ; i++) {
    buf[0] = i;
    for (char j = '0'; j <= '9'; j++) {
      buf[1] = j;
      for (char k = '0'; k <= '9'; k++) {
        buf[2] = k;
        buf[3] = 0;
        templ->Set(v8_str(buf), v8::Number::New(isolate, k));
      }
    }
  }

  Local<v8::Object> instance_1 =
      templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj_1"), instance_1)
            .FromJust());

  Local<Value> value_1 = CompileRun("obj_1.a");
  CHECK(value_1.IsEmpty());

  Local<v8::Object> instance_2 =
      templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj_2"), instance_2)
            .FromJust());

  Local<Value> value_2 = CompileRun("obj_2.a");
  CHECK(value_2.IsEmpty());
}


// This tests that we do not allow dictionary load/call inline caches
// to use functions that have not yet been compiled.  The potential
// problem of loading a function that has not yet been compiled can
// arise because we share code between contexts via the compilation
// cache.
THREADED_TEST(DictionaryICLoadedFunction) {
  v8::HandleScope scope(CcTest::isolate());
  // Test LoadIC.
  for (int i = 0; i < 2; i++) {
    LocalContext context;
    CHECK(context->Global()
              ->Set(context.local(), v8_str("tmp"), v8::True(CcTest::isolate()))
              .FromJust());
    context->Global()->Delete(context.local(), v8_str("tmp")).FromJust();
    CompileRun("for (var j = 0; j < 10; j++) new RegExp('');");
  }
  // Test CallIC.
  for (int i = 0; i < 2; i++) {
    LocalContext context;
    CHECK(context->Global()
              ->Set(context.local(), v8_str("tmp"), v8::True(CcTest::isolate()))
              .FromJust());
    context->Global()->Delete(context.local(), v8_str("tmp")).FromJust();
    CompileRun("for (var j = 0; j < 10; j++) RegExp('')");
  }
}


// Test that cross-context new calls use the context of the callee to
// create the new JavaScript object.
THREADED_TEST(CrossContextNew) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<Context> context0 = Context::New(isolate);
  v8::Local<Context> context1 = Context::New(isolate);

  // Allow cross-domain access.
  Local<String> token = v8_str("<security token>");
  context0->SetSecurityToken(token);
  context1->SetSecurityToken(token);

  // Set an 'x' property on the Object prototype and define a
  // constructor function in context0.
  context0->Enter();
  CompileRun("Object.prototype.x = 42; function C() {};");
  context0->Exit();

  // Call the constructor function from context0 and check that the
  // result has the 'x' property.
  context1->Enter();
  CHECK(context1->Global()
            ->Set(context1, v8_str("other"), context0->Global())
            .FromJust());
  Local<Value> value = CompileRun("var instance = new other.C(); instance.x");
  CHECK(value->IsInt32());
  CHECK_EQ(42, value->Int32Value(context1).FromJust());
  context1->Exit();
}


// Verify that we can clone an object
TEST(ObjectClone) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  const char* sample =
    "var rv = {};"      \
    "rv.alpha = 'hello';" \
    "rv.beta = 123;"     \
    "rv;";

  // Create an object, verify basics.
  Local<Value> val = CompileRun(sample);
  CHECK(val->IsObject());
  Local<v8::Object> obj = val.As<v8::Object>();
  obj->Set(env.local(), v8_str("gamma"), v8_str("cloneme")).FromJust();

  CHECK(v8_str("hello")
            ->Equals(env.local(),
                     obj->Get(env.local(), v8_str("alpha")).ToLocalChecked())
            .FromJust());
  CHECK(v8::Integer::New(isolate, 123)
            ->Equals(env.local(),
                     obj->Get(env.local(), v8_str("beta")).ToLocalChecked())
            .FromJust());
  CHECK(v8_str("cloneme")
            ->Equals(env.local(),
                     obj->Get(env.local(), v8_str("gamma")).ToLocalChecked())
            .FromJust());

  // Clone it.
  Local<v8::Object> clone = obj->Clone();
  CHECK(v8_str("hello")
            ->Equals(env.local(),
                     clone->Get(env.local(), v8_str("alpha")).ToLocalChecked())
            .FromJust());
  CHECK(v8::Integer::New(isolate, 123)
            ->Equals(env.local(),
                     clone->Get(env.local(), v8_str("beta")).ToLocalChecked())
            .FromJust());
  CHECK(v8_str("cloneme")
            ->Equals(env.local(),
                     clone->Get(env.local(), v8_str("gamma")).ToLocalChecked())
            .FromJust());

  // Set a property on the clone, verify each object.
  CHECK(clone->Set(env.local(), v8_str("beta"), v8::Integer::New(isolate, 456))
            .FromJust());
  CHECK(v8::Integer::New(isolate, 123)
            ->Equals(env.local(),
                     obj->Get(env.local(), v8_str("beta")).ToLocalChecked())
            .FromJust());
  CHECK(v8::Integer::New(isolate, 456)
            ->Equals(env.local(),
                     clone->Get(env.local(), v8_str("beta")).ToLocalChecked())
            .FromJust());
}


class OneByteVectorResource : public v8::String::ExternalOneByteStringResource {
 public:
  explicit OneByteVectorResource(v8::base::Vector<const char> vector)
      : data_(vector) {}
  ~OneByteVectorResource() override = default;
  size_t length() const override { return data_.length(); }
  const char* data() const override { return data_.begin(); }
  void Dispose() override {}

 private:
  v8::base::Vector<const char> data_;
};


class UC16VectorResource : public v8::String::ExternalStringResource {
 public:
  explicit UC16VectorResource(v8::base::Vector<const v8::base::uc16> vector)
      : data_(vector) {}
  ~UC16VectorResource() override = default;
  size_t length() const override { return data_.length(); }
  const v8::base::uc16* data() const override { return data_.begin(); }
  void Dispose() override {}

 private:
  v8::base::Vector<const v8::base::uc16> data_;
};

static void MorphAString(i::Tagged<i::String> string,
                         OneByteVectorResource* one_byte_resource,
                         UC16VectorResource* uc16_resource) {
  i::Isolate* isolate = CcTest::i_isolate();
  CHECK(i::StringShape(string).IsExternal());
  i::ReadOnlyRoots roots(CcTest::heap());
  if (string->IsOneByteRepresentation()) {
    // Check old map is not internalized or long.
    CHECK(string->map() == roots.external_one_byte_string_map());
    // Morph external string to be TwoByte string.
    string->set_map(isolate, roots.external_two_byte_string_map());
    i::Tagged<i::ExternalTwoByteString> morphed =
        i::Cast<i::ExternalTwoByteString>(string);
    CcTest::heap()->UpdateExternalString(morphed, string->length(), 0);
    morphed->SetResource(isolate, uc16_resource);
  } else {
    // Check old map is not internalized or long.
    CHECK(string->map() == roots.external_two_byte_string_map());
    // Morph external string to be one-byte string.
    string->set_map(isolate, roots.external_one_byte_string_map());
    i::Tagged<i::ExternalOneByteString> morphed =
        i::Cast<i::ExternalOneByteString>(string);
    CcTest::heap()->UpdateExternalString(morphed, string->length(), 0);
    morphed->SetResource(isolate, one_byte_resource);
  }
}

// Test that we can still flatten a string if the components it is built up
// from have been turned into 16 bit strings in the mean time.
THREADED_TEST(MorphCompositeStringTest) {
  char utf_buffer[129];
  const char* c_string = "Now is the time for all good men"
                         " to come to the aid of the party";
  uint16_t* two_byte_string = AsciiToTwoByteString(c_string);
  {
    LocalContext env;
    i::Factory* factory = CcTest::i_isolate()->factory();
    v8::Isolate* isolate = env->GetIsolate();
    i::Isolate* i_isolate = CcTest::i_isolate();
    v8::HandleScope scope(isolate);
    OneByteVectorResource one_byte_resource(
        v8::base::Vector<const char>(c_string, strlen(c_string)));
    UC16VectorResource uc16_resource(
        v8::base::Vector<const uint16_t>(two_byte_string, strlen(c_string)));

    Local<String> lhs(v8::Utils::
```