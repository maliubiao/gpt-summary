Response:
The user wants a summary of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. I need to identify the functionalities tested in this specific section of the file. The user also provided some conditions to check, such as whether the file could be a Torque file (it isn't, as it doesn't end with `.tq`), whether it's related to Javascript functionality (it is, as it's testing the V8 API), and to provide Javascript examples if relevant. I also need to look for code logic that can be explained with example inputs and outputs and to identify potential common programming errors illustrated by the tests. Finally, as this is part 18 of 36, I should keep in mind that the overall file is about testing various aspects of the V8 API.

Let's go through the code blocks:

1. **`TEST(ExternalTwoByte)`**: This test seems to be manipulating strings, specifically creating external strings and morphing them between one-byte and two-byte representations. It then performs string operations like concatenation and substring and checks the results.
2. **`TEST(CompileExternalTwoByteSource)`**: This test focuses on compiling Javascript code provided as external two-byte strings. It seems to be a regression test for a specific issue.
3. **`TEST(ReadOnlyPropertyInGlobalProto)`**: This test explores the behavior of read-only properties in the prototype chain of the global object. It checks if assignments to these read-only properties succeed or fail in different scenarios (direct assignment, `eval`, `with`).
4. **`TEST(CreateDataProperty)`**: This test examines the functionality of `CreateDataProperty` on Javascript objects and arrays, including cases where properties are non-configurable, indexed, or when the object is frozen. It also touches upon access check callbacks.
5. **`TEST(DefineOwnProperty)`**: This test is similar to the previous one but focuses on `DefineOwnProperty`, which allows more control over property attributes. It covers similar scenarios, including non-configurable properties, indexed properties, array length, read-only properties, and frozen objects.
6. **`TEST(DefineProperty)`**: This test further explores property definition using `DefineProperty` and `v8::PropertyDescriptor`. It tests various scenarios, including using data descriptors, generic descriptors, descriptors with undefined values, read-only attributes, accessor descriptors (getters and setters), and redefinition of existing properties.
7. **`THREADED_TEST(GetCurrentContextWhenNotInContext)`**: This test checks the behavior of `GetCurrentContext` when no context is active.
8. **`THREADED_TEST(InitGlobalVarInProtoChain)`**: This test verifies how variable declarations in the global scope interact with properties in the prototype chain.
9. **`THREADED_TEST(ReplaceConstantFunction)`**: This is a regression test related to cloning objects with constant function properties and then modifying the original object.
10. **`THREADED_TEST(ScriptContextDependence)`**: This test demonstrates the difference between context-dependent and context-independent scripts.
11. **`TEST(AsmJsWarning)`**: This test checks if specific warnings are triggered when compiling and running potentially invalid asm.js code.
12. **`TEST(ErrorLevelWarning)`**: This test verifies the functionality of error-level message listeners in V8.
13. **Promise rejection related code**: This part sets up callbacks to observe promise rejection events and captures related information like the rejection type, value, and stack trace.
The code snippet from `v8/test/cctest/test-api.cc` is part of the V8 JavaScript engine's test suite. This specific section focuses on testing various aspects of the V8 API related to **string manipulation, script compilation, property definition and manipulation on JavaScript objects, script context handling, and promise rejection events.**

Since `v8/test/cctest/test-api.cc` ends with `.cc`, it is a **C++ source file**, not a Torque file.

Yes, the functionality tested is heavily related to JavaScript. Here are some examples illustrating the JavaScript concepts being tested:

**1. String Manipulation (External Strings):**

```javascript
let str1 = "hello";
let str2 = "world";
let combined = str1 + str2; // Concatenation
let slice = str1.substring(1, 3); // Substring
```

The C++ code tests how V8 handles strings created from external resources, including operations like concatenation (`+`) and taking substrings (`substring`). It also checks the internal representation of strings (one-byte vs. two-byte).

**2. Script Compilation (External Sources):**

The `CompileExternalTwoByteSource` test verifies that V8 can correctly compile JavaScript code when the source is provided as an external two-byte string. This is relevant to how V8 might handle scripts loaded from external files or resources.

**3. Read-Only Properties in the Prototype Chain:**

```javascript
let proto = { x: 0 };
let obj = Object.create(proto);
Object.defineProperty(proto, 'y', { value: 0, writable: false });

function test() {
  x = 42; // Assigns to the global scope if not found in scope
  y = 43; // Throws an error in strict mode, otherwise fails silently
  return {x, y};
}

console.log(test()); // x will be 42, y will remain 0 (or throw an error)
```

The `ReadOnlyPropertyInGlobalProto` test checks how assignments behave when a read-only property exists in the prototype chain of the global object.

**4. Creating and Defining Properties (`CreateDataProperty`, `DefineOwnProperty`, `DefineProperty`):**

```javascript
let obj = {};

// Using Object.defineProperty
Object.defineProperty(obj, 'foo', { value: 23 });
Object.defineProperty(obj, 'bar', { value: 23, configurable: true });

// Directly assigning a property
obj.baz = 42;
```

These tests explore different ways to create and define properties on JavaScript objects, including setting their attributes like configurability, writability, and enumerability.

**5. Script Context Dependence:**

```javascript
// In one context:
globalThis.foo = 100;
eval("foo"); // Evaluates to 100

// In another context:
globalThis.foo = 101;
eval("foo"); // Evaluates to 101
```

The `ScriptContextDependence` test highlights that scripts compiled within a specific context are bound to that context's global object and its variables. Unbound scripts can be bound to different contexts.

**6. Asm.js Warnings:**

```javascript
function module() {
  "use asm";
  var x = "hi"; // This will likely trigger an asm.js validation warning
  return {};
}
module();
```

The `AsmJsWarning` test checks if V8 correctly identifies and reports warnings for code that doesn't conform to the asm.js specification.

**7. Promise Rejection Handling:**

```javascript
let promise = new Promise((resolve, reject) => {
  reject("Something went wrong!");
});

// Without a rejection handler, this will trigger a 'unhandledrejection' event
```

The code related to promise rejection tests how V8 handles promises that are rejected without a corresponding rejection handler.

**Code Logic Inference with Assumptions:**

**Test: `ExternalTwoByte`**

*   **Assumption Input:**  `one_byte_resource` contains the ASCII string "Now is the time for all good men to come to the aid of the party".
*   **Output:**
    *   `cons` will be the concatenation of `lhs` and `rhs`, resulting in "Now is the time for all good men to come to the aid of the partyNow is the time for all good men to come to the aid of the party".
    *   `slice` will be a substring of `lhs` from index 1 to `lhs.length - 1`, resulting in "ow is the time for all good men to come to the aid of the part".
    *   `slice_on_cons` will be a substring of the concatenated string from index 1 to `lhs.length * 2 - 1`, resulting in "ow is the time for all good men to come to the aid of the partyNow is the time for all good men to come to the aid of the part".
    *   The UTF-8 length of `cons` will be 128.
    *   After morphing the strings to two-byte, regular expressions are used to force flattening, and the final values of `cons`, `slice`, and `slice_on_cons` are checked against expected values.

**Common Programming Errors Illustrated:**

*   **Trying to modify non-configurable properties:** The tests for `CreateDataProperty`, `DefineOwnProperty`, and `DefineProperty` demonstrate the error of attempting to change or delete properties that have their `configurable` attribute set to `false`. This can lead to unexpected behavior or errors in JavaScript.

    ```javascript
    const obj = {};
    Object.defineProperty(obj, 'readOnly', { value: 10, configurable: false });

    // This will fail silently in non-strict mode or throw an error in strict mode
    delete obj.readOnly;
    Object.defineProperty(obj, 'readOnly', { value: 20 });
    ```

*   **Trying to write to read-only properties:** The `ReadOnlyPropertyInGlobalProto` test highlights the common error of trying to assign a value to a property that has its `writable` attribute set to `false`.

    ```javascript
    const obj = {};
    Object.defineProperty(obj, 'constant', { value: 10, writable: false });

    // This will fail silently in non-strict mode or throw an error in strict mode
    obj.constant = 20;
    ```

*   **Incorrect assumptions about script context:** The `ScriptContextDependence` test subtly illustrates the potential pitfall of assuming scripts will behave the same way across different V8 contexts if they rely on global variables.

**归纳一下它的功能 (Summary of its functionality):**

This part of `v8/test/cctest/test-api.cc` thoroughly tests the V8 API's functionalities related to:

*   **Handling of different string representations:** Testing the creation, manipulation, and internal transformations of strings, including external strings.
*   **Compilation of JavaScript code from various sources:**  Ensuring V8 can compile scripts provided as external resources.
*   **Property definition and manipulation:**  Verifying the correct behavior of methods like `CreateDataProperty`, `DefineOwnProperty`, and `DefineProperty`, including their interaction with property attributes (configurable, writable, enumerable).
*   **Prototype chain and property access:** Testing how V8 handles read-only properties in the prototype chain and the shadowing of properties.
*   **Script context management:** Demonstrating the concept of script context dependence and how scripts are bound to specific global scopes.
*   **Error and warning reporting:** Checking V8's ability to generate and report warnings for non-conforming code (like asm.js).
*   **Promise rejection handling:**  Testing the mechanism for reporting and observing unhandled promise rejections.

Essentially, this section focuses on ensuring the robustness and correctness of fundamental V8 API features that are crucial for executing JavaScript code and managing JavaScript objects and their properties.

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第18部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
ToLocal(
        factory->NewExternalStringFromOneByte(&one_byte_resource)
            .ToHandleChecked()));
    Local<String> rhs(v8::Utils::ToLocal(
        factory->NewExternalStringFromOneByte(&one_byte_resource)
            .ToHandleChecked()));

    CHECK(env->Global()->Set(env.local(), v8_str("lhs"), lhs).FromJust());
    CHECK(env->Global()->Set(env.local(), v8_str("rhs"), rhs).FromJust());

    CompileRun(
        "var cons = lhs + rhs;"
        "var slice = lhs.substring(1, lhs.length - 1);"
        "var slice_on_cons = (lhs + rhs).substring(1, lhs.length *2 - 1);");

    CHECK(lhs->IsOneByte());
    CHECK(rhs->IsOneByte());

    i::DirectHandle<i::String> ilhs = v8::Utils::OpenDirectHandle(*lhs);
    i::DirectHandle<i::String> irhs = v8::Utils::OpenDirectHandle(*rhs);
    MorphAString(*ilhs, &one_byte_resource, &uc16_resource);
    MorphAString(*irhs, &one_byte_resource, &uc16_resource);

    // This should UTF-8 without flattening, since everything is ASCII.
    Local<String> cons =
        v8_compile("cons")->Run(env.local()).ToLocalChecked().As<String>();
    CHECK_EQ(128, cons->Utf8LengthV2(isolate));
    CHECK_EQ(129, cons->WriteUtf8V2(isolate, utf_buffer, sizeof(utf_buffer),
                                    String::WriteFlags::kNullTerminate));
    CHECK_EQ(0, strcmp(
        utf_buffer,
        "Now is the time for all good men to come to the aid of the party"
        "Now is the time for all good men to come to the aid of the party"));

    // Now do some stuff to make sure the strings are flattened, etc.
    CompileRun(
        "/[^a-z]/.test(cons);"
        "/[^a-z]/.test(slice);"
        "/[^a-z]/.test(slice_on_cons);");
    const char* expected_cons =
        "Now is the time for all good men to come to the aid of the party"
        "Now is the time for all good men to come to the aid of the party";
    const char* expected_slice =
        "ow is the time for all good men to come to the aid of the part";
    const char* expected_slice_on_cons =
        "ow is the time for all good men to come to the aid of the party"
        "Now is the time for all good men to come to the aid of the part";
    CHECK(v8_str(expected_cons)
              ->Equals(env.local(), env->Global()
                                        ->Get(env.local(), v8_str("cons"))
                                        .ToLocalChecked())
              .FromJust());
    CHECK(v8_str(expected_slice)
              ->Equals(env.local(), env->Global()
                                        ->Get(env.local(), v8_str("slice"))
                                        .ToLocalChecked())
              .FromJust());
    CHECK(v8_str(expected_slice_on_cons)
              ->Equals(env.local(),
                       env->Global()
                           ->Get(env.local(), v8_str("slice_on_cons"))
                           .ToLocalChecked())
              .FromJust());

    // This avoids the GC from trying to free a stack allocated resource.
    if (IsExternalOneByteString(*ilhs))
      i::Cast<i::ExternalOneByteString>(*ilhs)->SetResource(i_isolate, nullptr);
    else
      i::Cast<i::ExternalTwoByteString>(*ilhs)->SetResource(i_isolate, nullptr);
    if (IsExternalOneByteString(*irhs))
      i::Cast<i::ExternalOneByteString>(*irhs)->SetResource(i_isolate, nullptr);
    else
      i::Cast<i::ExternalTwoByteString>(*irhs)->SetResource(i_isolate, nullptr);
  }
  i::DeleteArray(two_byte_string);
}


TEST(CompileExternalTwoByteSource) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // This is a very short list of sources, which currently is to check for a
  // regression caused by r2703.
  const char* one_byte_sources[] = {
      "0.5",
      "-0.5",   // This mainly testes PushBack in the Scanner.
      "--0.5",  // This mainly testes PushBack in the Scanner.
      nullptr};

  // Compile the sources as external two byte strings.
  for (int i = 0; one_byte_sources[i] != nullptr; i++) {
    uint16_t* two_byte_string = AsciiToTwoByteString(one_byte_sources[i]);
    TestResource* uc16_resource = new TestResource(two_byte_string);
    v8::Local<v8::String> source =
        v8::String::NewExternalTwoByte(context->GetIsolate(), uc16_resource)
            .ToLocalChecked();
    v8::Script::Compile(context.local(), source).FromMaybe(Local<Script>());
  }
}

// Test that we cannot set a property on the global object if there
// is a read-only property in the prototype chain.
TEST(ReadOnlyPropertyInGlobalProto) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  LocalContext context(nullptr, templ);
  v8::Local<v8::Object> global = context->Global();
  v8::Local<v8::Object> global_proto = v8::Local<v8::Object>::Cast(
      global->Get(context.local(), v8_str("__proto__")).ToLocalChecked());
  global_proto->DefineOwnProperty(context.local(), v8_str("x"),
                                  v8::Integer::New(isolate, 0), v8::ReadOnly)
      .FromJust();
  global_proto->DefineOwnProperty(context.local(), v8_str("y"),
                                  v8::Integer::New(isolate, 0), v8::ReadOnly)
      .FromJust();
  // Check without 'eval' or 'with'.
  v8::Local<v8::Value> res =
      CompileRun("function f() { x = 42; return x; }; f()");
  CHECK(v8::Integer::New(isolate, 0)->Equals(context.local(), res).FromJust());
  // Check with 'eval'.
  res = CompileRun("function f() { eval('1'); y = 43; return y; }; f()");
  CHECK(v8::Integer::New(isolate, 0)->Equals(context.local(), res).FromJust());
  // Check with 'with'.
  res = CompileRun("function f() { with (this) { y = 44 }; return y; }; f()");
  CHECK(v8::Integer::New(isolate, 0)->Equals(context.local(), res).FromJust());
}


TEST(CreateDataProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  CompileRun(
      "var a = {};"
      "var b = [];"
      "Object.defineProperty(a, 'foo', {value: 23});"
      "Object.defineProperty(a, 'bar', {value: 23, configurable: true});");

  v8::Local<v8::Object> obj = v8::Local<v8::Object>::Cast(
      env->Global()->Get(env.local(), v8_str("a")).ToLocalChecked());
  v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast(
      env->Global()->Get(env.local(), v8_str("b")).ToLocalChecked());
  {
    // Can't change a non-configurable properties.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->CreateDataProperty(env.local(), v8_str("foo"),
                                   v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK(obj->CreateDataProperty(env.local(), v8_str("bar"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("bar")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set a regular property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->CreateDataProperty(env.local(), v8_str("blub"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("blub")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set an indexed property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->CreateDataProperty(env.local(), v8_str("1"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Special cases for arrays.
    v8::TryCatch try_catch(isolate);
    CHECK(!arr->CreateDataProperty(env.local(), v8_str("length"),
                                   v8::Integer::New(isolate, 1)).FromJust());
    CHECK(!try_catch.HasCaught());
  }
  {
    // Special cases for arrays: index exceeds the array's length
    v8::TryCatch try_catch(isolate);
    CHECK(arr->CreateDataProperty(env.local(), 1, v8::Integer::New(isolate, 23))
              .FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(2U, arr->Length());
    v8::Local<v8::Value> val = arr->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(23.0, val->NumberValue(env.local()).FromJust());

    // Set an existing entry.
    CHECK(arr->CreateDataProperty(env.local(), 0, v8::Integer::New(isolate, 42))
              .FromJust());
    CHECK(!try_catch.HasCaught());
    val = arr->Get(env.local(), 0).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  CompileRun("Object.freeze(a);");
  {
    // Can't change non-extensible objects.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->CreateDataProperty(env.local(), v8_str("baz"),
                                   v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessAlwaysBlocked);
  v8::Local<v8::Object> access_checked =
      templ->NewInstance(env.local()).ToLocalChecked();
  {
    v8::TryCatch try_catch(isolate);
    CHECK(access_checked->CreateDataProperty(env.local(), v8_str("foo"),
                                             v8::Integer::New(isolate, 42))
              .IsNothing());
    CHECK(try_catch.HasCaught());
  }
}


TEST(DefineOwnProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  CompileRun(
      "var a = {};"
      "var b = [];"
      "Object.defineProperty(a, 'foo', {value: 23});"
      "Object.defineProperty(a, 'bar', {value: 23, configurable: true});");

  v8::Local<v8::Object> obj = v8::Local<v8::Object>::Cast(
      env->Global()->Get(env.local(), v8_str("a")).ToLocalChecked());
  v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast(
      env->Global()->Get(env.local(), v8_str("b")).ToLocalChecked());
  {
    // Can't change a non-configurable properties.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->DefineOwnProperty(env.local(), v8_str("foo"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK(obj->DefineOwnProperty(env.local(), v8_str("bar"),
                                 v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("bar")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set a regular property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineOwnProperty(env.local(), v8_str("blub"),
                                 v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("blub")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set an indexed property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineOwnProperty(env.local(), v8_str("1"),
                                 v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Special cases for arrays.
    v8::TryCatch try_catch(isolate);
    CHECK(!arr->DefineOwnProperty(env.local(), v8_str("length"),
                                  v8::Integer::New(isolate, 1)).FromJust());
    CHECK(!try_catch.HasCaught());
  }
  {
    // Special cases for arrays: index exceeds the array's length
    v8::TryCatch try_catch(isolate);
    CHECK(arr->DefineOwnProperty(env.local(), v8_str("1"),
                                 v8::Integer::New(isolate, 23)).FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(2U, arr->Length());
    v8::Local<v8::Value> val = arr->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(23.0, val->NumberValue(env.local()).FromJust());

    // Set an existing entry.
    CHECK(arr->DefineOwnProperty(env.local(), v8_str("0"),
                                 v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    val = arr->Get(env.local(), 0).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set a non-writable property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineOwnProperty(env.local(), v8_str("lala"),
                                 v8::Integer::New(isolate, 42),
                                 v8::ReadOnly).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("lala")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
    CHECK_EQ(v8::ReadOnly, obj->GetPropertyAttributes(
                                    env.local(), v8_str("lala")).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  CompileRun("Object.freeze(a);");
  {
    // Can't change non-extensible objects.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->DefineOwnProperty(env.local(), v8_str("baz"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessAlwaysBlocked);
  v8::Local<v8::Object> access_checked =
      templ->NewInstance(env.local()).ToLocalChecked();
  {
    v8::TryCatch try_catch(isolate);
    CHECK(access_checked->DefineOwnProperty(env.local(), v8_str("foo"),
                                            v8::Integer::New(isolate, 42))
              .IsNothing());
    CHECK(try_catch.HasCaught());
  }
}

TEST(DefineProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Name> p;

  CompileRun(
      "var a = {};"
      "var b = [];"
      "Object.defineProperty(a, 'v1', {value: 23});"
      "Object.defineProperty(a, 'v2', {value: 23, configurable: true});");

  v8::Local<v8::Object> obj = v8::Local<v8::Object>::Cast(
      env->Global()->Get(env.local(), v8_str("a")).ToLocalChecked());
  v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast(
      env->Global()->Get(env.local(), v8_str("b")).ToLocalChecked());

  v8::PropertyDescriptor desc(v8_num(42));
  {
    // Use a data descriptor.

    // Cannot change a non-configurable property.
    p = v8_str("v1");
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->DefineProperty(env.local(), p, desc).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(23.0, val->NumberValue(env.local()).FromJust());

    // Change a configurable property.
    p = v8_str("v2");
    obj->DefineProperty(env.local(), p, desc).FromJust();
    CHECK(obj->DefineProperty(env.local(), p, desc).FromJust());
    CHECK(!try_catch.HasCaught());
    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());

    // Check that missing writable has default value false.
    p = v8_str("v12");
    CHECK(obj->DefineProperty(env.local(), p, desc).FromJust());
    CHECK(!try_catch.HasCaught());
    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
    v8::PropertyDescriptor desc2(v8_num(43));
    CHECK(!obj->DefineProperty(env.local(), p, desc2).FromJust());
    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Set a regular property.
    p = v8_str("v3");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set an indexed property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), v8_str("1"), desc).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // No special case when changing array length.
    v8::TryCatch try_catch(isolate);
    // Use a writable descriptor, otherwise the next test, that changes
    // the array length will fail.
    v8::PropertyDescriptor desc_writable(v8_num(42), true);
    CHECK(arr->DefineProperty(env.local(), v8_str("length"), desc_writable)
              .FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Special cases for arrays: index exceeds the array's length.
    v8::TryCatch try_catch(isolate);
    CHECK(arr->DefineProperty(env.local(), v8_str("100"), desc).FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(101U, arr->Length());
    v8::Local<v8::Value> val = arr->Get(env.local(), 100).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());

    // Set an existing entry.
    CHECK(arr->DefineProperty(env.local(), v8_str("0"), desc).FromJust());
    CHECK(!try_catch.HasCaught());
    val = arr->Get(env.local(), 0).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Use a generic descriptor.
    v8::PropertyDescriptor desc_generic;

    p = v8_str("v4");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_generic).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsUndefined());

    obj->Set(env.local(), p, v8_num(1)).FromJust();
    CHECK(!try_catch.HasCaught());

    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsUndefined());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Use a data descriptor with undefined value.
    v8::PropertyDescriptor desc_empty(v8::Undefined(isolate));

    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_empty).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsUndefined());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Use a descriptor with attribute == v8::ReadOnly.
    v8::PropertyDescriptor desc_read_only(v8_num(42), false);
    desc_read_only.set_enumerable(true);
    desc_read_only.set_configurable(true);

    p = v8_str("v5");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_read_only).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
    CHECK_EQ(v8::ReadOnly,
             obj->GetPropertyAttributes(env.local(), p).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Use an accessor descriptor with empty handles.
    v8::PropertyDescriptor desc_empty(v8::Undefined(isolate),
                                      v8::Undefined(isolate));

    p = v8_str("v6");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_empty).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsUndefined());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Use an accessor descriptor.
    CompileRun(
        "var set = function(x) {this.val = 2*x;};"
        "var get = function() {return this.val || 0;};");

    v8::Local<v8::Function> get = v8::Local<v8::Function>::Cast(
        env->Global()->Get(env.local(), v8_str("get")).ToLocalChecked());
    v8::Local<v8::Function> set = v8::Local<v8::Function>::Cast(
        env->Global()->Get(env.local(), v8_str("set")).ToLocalChecked());
    v8::PropertyDescriptor desc_getter_setter(get, set);

    p = v8_str("v7");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_getter_setter).FromJust());
    CHECK(!try_catch.HasCaught());

    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(0.0, val->NumberValue(env.local()).FromJust());
    CHECK(!try_catch.HasCaught());

    obj->Set(env.local(), p, v8_num(7)).FromJust();
    CHECK(!try_catch.HasCaught());

    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(14.0, val->NumberValue(env.local()).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Redefine an existing property.

    // desc = {value: 42, enumerable: true}
    v8::PropertyDescriptor desc42(v8_num(42));
    desc42.set_enumerable(true);

    p = v8_str("v8");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc42).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {enumerable: true}
    v8::PropertyDescriptor desc_true((v8::Local<v8::Value>()));
    desc_true.set_enumerable(true);

    // Successful redefinition because all present attributes have the same
    // value as the current descriptor.
    CHECK(obj->DefineProperty(env.local(), p, desc_true).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {}
    v8::PropertyDescriptor desc_empty;
    // Successful redefinition because no attributes are overwritten in the
    // current descriptor.
    CHECK(obj->DefineProperty(env.local(), p, desc_empty).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {enumerable: false}
    v8::PropertyDescriptor desc_false((v8::Local<v8::Value>()));
    desc_false.set_enumerable(false);
    // Not successful because we cannot define a different value for enumerable.
    CHECK(!obj->DefineProperty(env.local(), p, desc_false).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Redefine a property that has a getter.
    CompileRun("var get = function() {};");
    v8::Local<v8::Function> get = v8::Local<v8::Function>::Cast(
        env->Global()->Get(env.local(), v8_str("get")).ToLocalChecked());

    // desc = {get: function() {}}
    v8::PropertyDescriptor desc_getter(get, v8::Local<v8::Function>());
    v8::TryCatch try_catch(isolate);

    p = v8_str("v9");
    CHECK(obj->DefineProperty(env.local(), p, desc_getter).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc_empty = {}
    // Successful because we are not redefining the current getter.
    v8::PropertyDescriptor desc_empty;
    CHECK(obj->DefineProperty(env.local(), p, desc_empty).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {get: function() {}}
    // Successful because we redefine the getter with its current value.
    CHECK(obj->DefineProperty(env.local(), p, desc_getter).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {get: undefined}
    v8::PropertyDescriptor desc_undefined(v8::Undefined(isolate),
                                          v8::Local<v8::Function>());
    // Not successful because we cannot redefine with the current value of get
    // with undefined.
    CHECK(!obj->DefineProperty(env.local(), p, desc_undefined).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  CompileRun("Object.freeze(a);");
  {
    // We cannot change non-extensible objects.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->DefineProperty(env.local(), v8_str("v10"), desc).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessAlwaysBlocked);
  v8::Local<v8::Object> access_checked =
      templ->NewInstance(env.local()).ToLocalChecked();
  {
    v8::TryCatch try_catch(isolate);
    CHECK(access_checked->DefineProperty(env.local(), v8_str("v11"), desc)
              .IsNothing());
    CHECK(try_catch.HasCaught());
  }
}

THREADED_TEST(GetCurrentContextWhenNotInContext) {
  i::Isolate* isolate = CcTest::i_isolate();
  CHECK_NOT_NULL(isolate);
  CHECK(isolate->context().is_null());
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8::HandleScope scope(v8_isolate);
  // The following should not crash, but return an empty handle.
  v8::Local<v8::Context> current = v8_isolate->GetCurrentContext();
  CHECK(current.IsEmpty());
}


// Check that a variable declaration with no explicit initialization
// value does shadow an existing property in the prototype chain.
THREADED_TEST(InitGlobalVarInProtoChain) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  // Introduce a variable in the prototype chain.
  CompileRun("__proto__.x = 42");
  v8::Local<v8::Value> result = CompileRun("var x = 43; x");
  CHECK(!result->IsUndefined());
  CHECK_EQ(43, result->Int32Value(context.local()).FromJust());
}


// Regression test for issue 398.
// If a function is added to an object, creating a constant function
// field, and the result is cloned, replacing the constant function on the
// original should not affect the clone.
// See http://code.google.com/p/v8/issues/detail?id=398
THREADED_TEST(ReplaceConstantFunction) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  v8::Local<v8::FunctionTemplate> func_templ =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> foo_string = v8_str("foo");
  obj->Set(context.local(), foo_string,
           func_templ->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<v8::Object> obj_clone = obj->Clone();
  obj_clone->Set(context.local(), foo_string, v8_str("Hello")).FromJust();
  CHECK(!obj->Get(context.local(), foo_string).ToLocalChecked()->IsUndefined());
}

THREADED_TEST(ScriptContextDependence) {
  LocalContext c1;
  v8::HandleScope scope(c1->GetIsolate());
  const char source[] = "foo";
  v8::Local<v8::Script> dep = v8_compile(source);
  v8::ScriptCompiler::Source script_source(
      v8::String::NewFromUtf8Literal(c1->GetIsolate(), source));
  v8::Local<v8::UnboundScript> indep =
      v8::ScriptCompiler::CompileUnboundScript(c1->GetIsolate(), &script_source)
          .ToLocalChecked();
  c1->Global()
      ->Set(c1.local(), v8::String::NewFromUtf8Literal(c1->GetIsolate(), "foo"),
            v8::Integer::New(c1->GetIsolate(), 100))
      .FromJust();
  CHECK_EQ(
      dep->Run(c1.local()).ToLocalChecked()->Int32Value(c1.local()).FromJust(),
      100);
  CHECK_EQ(indep->BindToCurrentContext()
               ->Run(c1.local())
               .ToLocalChecked()
               ->Int32Value(c1.local())
               .FromJust(),
           100);
  LocalContext c2;
  c2->Global()
      ->Set(c2.local(), v8::String::NewFromUtf8Literal(c2->GetIsolate(), "foo"),
            v8::Integer::New(c2->GetIsolate(), 101))
      .FromJust();
  CHECK_EQ(
      dep->Run(c2.local()).ToLocalChecked()->Int32Value(c2.local()).FromJust(),
      100);
  CHECK_EQ(indep->BindToCurrentContext()
               ->Run(c2.local())
               .ToLocalChecked()
               ->Int32Value(c2.local())
               .FromJust(),
           101);
}

#if V8_ENABLE_WEBASSEMBLY
static int asm_warning_triggered = 0;

static void AsmJsWarningListener(v8::Local<v8::Message> message,
                                 v8::Local<Value>) {
  CHECK_EQ(v8::Isolate::kMessageWarning, message->ErrorLevel());
  asm_warning_triggered = 1;
}

TEST(AsmJsWarning) {
  i::v8_flags.validate_asm = true;
  if (i::v8_flags.suppress_asm_messages) return;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  asm_warning_triggered = 0;
  isolate->AddMessageListenerWithErrorLevel(AsmJsWarningListener,
                                            v8::Isolate::kMessageAll);
  CompileRun(
      "function module() {\n"
      "  'use asm';\n"
      "  var x = 'hi';\n"
      "  return {};\n"
      "}\n"
      "module();");
  int kExpectedWarnings = 1;
  CHECK_EQ(kExpectedWarnings, asm_warning_triggered);
  isolate->RemoveMessageListeners(AsmJsWarningListener);
}
#endif  // V8_ENABLE_WEBASSEMBLY

static int error_level_message_count = 0;
static int expected_error_level = 0;

static void ErrorLevelListener(v8::Local<v8::Message> message,
                               v8::Local<Value>) {
  DCHECK_EQ(expected_error_level, message->ErrorLevel());
  ++error_level_message_count;
}

TEST(ErrorLevelWarning) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);

  const char* source = "fake = 1;";
  v8::Local<v8::Script> lscript = CompileWithOrigin(source, "test", false);
  i::DirectHandle<i::SharedFunctionInfo> obj = i::Cast<i::SharedFunctionInfo>(
      v8::Utils::OpenDirectHandle(*lscript->GetUnboundScript()));
  CHECK(IsScript(obj->script()));
  i::Handle<i::Script> script(i::Cast<i::Script>(obj->script()), i_isolate);

  int levels[] = {
      v8::Isolate::kMessageLog, v8::Isolate::kMessageInfo,
      v8::Isolate::kMessageDebug, v8::Isolate::kMessageWarning,
  };
  error_level_message_count = 0;
  isolate->AddMessageListenerWithErrorLevel(ErrorLevelListener,
                                            v8::Isolate::kMessageAll);
  for (size_t i = 0; i < arraysize(levels); i++) {
    i::MessageLocation location(script, 0, 0);
    i::DirectHandle<i::String> msg(i_isolate->factory()->InternalizeString(
        v8::base::StaticCharVector("test")));
    i::DirectHandle<i::JSMessageObject> message =
        i::MessageHandler::MakeMessageObject(
            i_isolate, i::MessageTemplate::kAsmJsInvalid, &location, msg);
    message->set_error_level(levels[i]);
    expected_error_level = levels[i];
    i::MessageHandler::ReportMessage(i_isolate, &location, message);
  }
  isolate->RemoveMessageListeners(ErrorLevelListener);
  DCHECK_EQ(arraysize(levels), error_level_message_count);
}

v8::PromiseRejectEvent reject_event = v8::kPromiseRejectWithNoHandler;
int promise_reject_counter = 0;
int promise_revoke_counter = 0;
int promise_reject_after_resolved_counter = 0;
int promise_resolve_after_resolved_counter = 0;
int promise_reject_msg_line_number = -1;
int promise_reject_msg_column_number = -1;
int promise_reject_line_number = -1;
int promise_reject_column_number = -1;
int promise_reject_frame_count = -1;
bool promise_reject_is_shared_cross_origin = false;

void PromiseRejectCallback(v8::PromiseRejectMessage reject_message) {
  v8::Local<v8::Object> global = CcTest::global();
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK_NE(v8::Promise::PromiseState::kPending,
           reject_message.GetPromise()->State());
  switch (reject_message.GetEvent()) {
    case v8::kPromiseRejectWithNoHandler: {
      promise_reject_counter++;
      global->Set(context, v8_str("rejected"), reject_message.GetPromise())
          .FromJust();
      global->Set(context, v8_str("value"), reject_message.GetValue())
          .FromJust();
      v8::Local<v8::Message> message = v8::Exception::CreateMessage(
          CcTest::isolate(), reject_message.GetValue());
      v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();

      promise_reject_msg_line_number =
          message->GetLineNumber(context).FromJust();
      promise_reject_msg_column_number =
          message->GetStartColumn(context).FromJust() + 1;
      promise_reject_is_shared_cross_origin =
          message->IsSharedCrossOrigin();

      if (!stack_trace.IsEmpty()) {
        promise_reject_frame_count = stack_trace->GetFrameCount();
        if (promise_reject_frame_count > 0) {
          CHECK(stack_trace->GetFrame(CcTest::isolate(), 0)
                    ->GetScriptName()
                    ->Equals(context, v8_str("pro"))
                    .FromJust());
          promise_reject_line_number =
              stack_trace->GetFrame(CcTest::isolate(), 0)->GetLineNumber();
          promise_reject_column_number =
              sta
```