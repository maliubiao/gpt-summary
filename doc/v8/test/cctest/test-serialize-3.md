Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a V8 test file named `test-serialize.cc`.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the file type:** The filename ends with `.cc`, indicating it's a C++ source file, not a Torque file (which would end in `.tq`). This answers the first part of the prompt.

2. **Recognize the context:** The path `v8/test/cctest/` strongly suggests this is a test file within the V8 JavaScript engine project. The name `test-serialize.cc` further hints at its purpose: testing serialization and deserialization functionalities.

3. **Analyze the code structure:** The code primarily consists of multiple `UNINITIALIZED_TEST` macros. These are likely part of a testing framework (like gtest, though V8 has its own). Each test case seems to focus on a specific aspect of serialization.

4. **Examine individual test cases:** Go through each `UNINITIALIZED_TEST` block and try to understand its objective by looking at the operations performed:
    * **`ReinitializeHashSeedRehashable` (two occurrences):** These tests involve setting up a snapshot creator, creating objects (including arrays and dictionaries), serializing the snapshot, then re-initializing a new isolate with the snapshot and verifying that hash seeds and object properties are correctly restored after rehashing. The use of `%NormalizeElements` and `%OptimizeObjectForAddingMultipleProperties` suggests testing the serialization of different object representations.
    * **`ClassFields`:** This test defines several classes with various kinds of fields (private, public, with initializers, etc.) and checks if they are correctly serialized and deserialized.
    * **`ClassFieldsReferencePrivateInInitializer`:**  Focuses on how private fields referenced within initializers are handled during serialization, including scenarios with `eval`.
    * **`ClassFieldsReferenceClassVariable`:** Tests serialization of classes where fields reference the class constructor itself.
    * **`ClassFieldsNested`:** Deals with nested classes and their private fields during serialization.
    * **`ClassPrivateMethods`:**  Tests the serialization of classes with private methods and accessors.
    * **`ClassFieldsWithInheritance`:** Examines how class inheritance, including `super()` calls, interacts with field serialization.
    * **`ClassFieldsRecalcPrivateNames`:**  Seems to be testing the correct handling of private name resolution in nested classes and inheritance scenarios during serialization.
    * **`ClassFieldsWithBindings`:**  Focuses on how different variable bindings (`var`, `let`, `const`) within classes are serialized.
    * **`WeakArraySerializationInSnapshot`:** This test checks that weak arrays (specifically in ScriptInfos) are handled correctly when creating and restoring snapshots. It verifies that these weak references point to the expected objects after deserialization.
    * **`WeakArraySerializationInCodeCache`:** Similar to the previous test, but focuses on weak arrays within the code cache mechanism.
    * **`CachedFunctionHostDefinedOption`:**  Tests the serialization and deserialization of functions that use host-defined options, particularly in the context of dynamic imports.
    * **`CachedUnboundScriptHostDefinedOption`:**  Similar to the previous test, but with unbound scripts.

5. **Identify common themes and functionalities:**  The dominant theme is **snapshotting and deserialization**. The tests cover various aspects:
    * **Basic object and data serialization:**  Simple values, arrays, and objects.
    * **Handling of different object storage modes:** Fast vs. dictionary mode.
    * **Class features:** Fields (private and public, with initializers), private methods, inheritance.
    * **Scoping and bindings:** How variables and constants defined within classes are serialized.
    * **Weak references:** Ensuring weak references in metadata survive serialization and deserialization.
    * **Code caching:**  Serializing and deserializing compiled code along with its metadata.
    * **Host-defined options:**  Preserving custom data associated with scripts and functions during caching.
    * **Rehashing:**  Testing the ability to rehash objects when the hash seed changes.

6. **Relate to JavaScript functionality:** Many of the tests directly correspond to JavaScript language features. Examples include:
    * Object and array creation (`var o = {}`, `var a = []`).
    * Class syntax (`class MyClass { ... }`).
    * Private class members (`#field`, `#method`).
    * Inheritance (`extends`).
    * Dynamic imports (`import()`).

7. **Consider potential programming errors:**  While the code itself is test code, the *features being tested* relate to potential user errors. For instance, misunderstanding how private fields work, especially in inheritance or with `eval`, could lead to runtime errors. Incorrect handling of asynchronous operations with dynamic imports is another area.

8. **Formulate the summary:** Combine the observations from the previous steps into a concise description of the file's functionality. Highlight the key areas being tested and their relevance to V8 and JavaScript.

9. **Address specific points in the prompt:** Ensure that the answer explicitly addresses whether the file is Torque (it's not), provides JavaScript examples, discusses code logic and potential errors, and acknowledges the part number.

By following these steps, we can construct a comprehensive and accurate answer to the user's request.
```cpp
s.add(1);"
          "s.add(globalThis);");
      ExpectInt32("m.get('b')", 2);
      ExpectTrue("s.has(1)");
      ExpectTrue("s.has(globalThis)");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    CHECK(blob.CanBeRehashed());
  }

  i::v8_flags.hash_seed = 1337;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    // Check that rehashing has been performed.
    CHECK_EQ(static_cast<uint64_t>(1337),
             HashSeed(reinterpret_cast<i::Isolate*>(isolate)));
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectInt32("m.get('b')", 2);
    ExpectTrue("s.has(1)");
    ExpectTrue("s.has(globalThis)");
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ReinitializeHashSeedRehashable) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      // Create dictionary mode object.
      CompileRun(
          "var a = new Array(10000);"
          "%NormalizeElements(a);"
          "a[133] = 1;"
          "a[177] = 2;"
          "a[971] = 3;"
          "a[7997] = 4;"
          "a[2111] = 5;"
          "var o = {};"
          "%OptimizeObjectForAddingMultipleProperties(o, 3);"
          "o.a = 1;"
          "o.b = 2;"
          "o.c = 3;"
          "var p = { foo: 1 };"  // Test rehashing of transition arrays.
          "p = JSON.parse('{\"foo\": {\"x\": 1}}');");
      i::Handle<i::Object> i_a = v8::Utils::OpenHandle(*CompileRun("a"));
      i::Handle<i::Object> i_o = v8::Utils::OpenHandle(*CompileRun("o"));
      CHECK(IsJSArray(*i_a));
      CHECK(IsJSObject(*i_a));
      CHECK(!i::Cast<i::JSArray>(i_a)->HasFastElements());
      CHECK(!i::Cast<i::JSObject>(i_o)->HasFastProperties());
      ExpectInt32("a[2111]", 5);
      ExpectInt32("o.c", 3);
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    CHECK(blob.CanBeRehashed());
  }

  i::v8_flags.hash_seed = 1337;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    // Check that rehashing has been performed.
    CHECK_EQ(static_cast<uint64_t>(1337),
             HashSeed(reinterpret_cast<i::Isolate*>(isolate)));
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    i::Handle<i::Object> i_a = v8::Utils::OpenHandle(*CompileRun("a"));
    i::Handle<i::Object> i_o = v8::Utils::OpenHandle(*CompileRun("o"));
    CHECK(IsJSArray(*i_a));
    CHECK(IsJSObject(*i_a));
    CHECK(!i::Cast<i::JSArray>(i_a)->HasFastElements());
    CHECK(!i::Cast<i::JSObject>(i_o)->HasFastProperties());
    ExpectInt32("a[2111]", 5);
    ExpectInt32("o.c", 3);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFields) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class ClassWithFieldInitializer {"
          "  #field = 1;"
          "  constructor(val) {"
          "    this.#field = val;"
          "  }"
          "  get field() {"
          "    return this.#field;"
          "  }"
          "}"
          "class ClassWithDefaultConstructor {"
          "  #field = 42;"
          "  get field() {"
          "    return this.#field;"
          "  }"
          "}"
          "class ClassWithFieldDeclaration {"
          "  #field;"
          "  constructor(val) {"
          "    this.#field = val;"
          "  }"
          "  get field() {"
          "    return this.#field;"
          "  }"
          "}"
          "class ClassWithPublicField {"
          "  field = 1;"
          "  constructor(val) {"
          "    this.field = val;"
          "  }"
          "}"
          "class ClassWithFunctionField {"
          "  field = 123;"
          "  func = () => { return this.field; }"
          "}"
          "class ClassWithThisInInitializer {"
          "  #field = 123;"
          "  field = this.#field;"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectInt32("(new ClassWithFieldInitializer(123)).field", 123);
    ExpectInt32("(new ClassWithDefaultConstructor()).field", 42);
    ExpectInt32("(new ClassWithFieldDeclaration(123)).field", 123);
    ExpectInt32("(new ClassWithPublicField(123)).field", 123);
    ExpectInt32("(new ClassWithFunctionField()).func()", 123);
    ExpectInt32("(new ClassWithThisInInitializer()).field", 123);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsReferencePrivateInInitializer) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class A {"
          "  #a = 42;"
          "  a = this.#a;"
          "}"
          "let str;"
          "class ClassWithEval {"
          "  field = eval(str);"
          "}"
          "class ClassWithPrivateAndEval {"
          "  #field = 42;"
          "  field = eval(str);"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectInt32("(new A()).a", 42);
    v8::TryCatch try_catch(isolate);
    CompileRun("str = 'this.#nonexistent'; (new ClassWithEval()).field");
    CHECK(try_catch.HasCaught());
    try_catch.Reset();
    ExpectInt32("str = 'this.#field'; (new ClassWithPrivateAndEval()).field",
                42);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsReferenceClassVariable) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class PrivateFieldClass {"
          "  #consturctor = PrivateFieldClass;"
          "  func() {"
          "    return this.#consturctor;"
          "  }"
          "}"
          "class PublicFieldClass {"
          "  ctor = PublicFieldClass;"
          "  func() {"
          "    return this.ctor;"
          "  }"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectTrue("new PrivateFieldClass().func() === PrivateFieldClass");
    ExpectTrue("new PublicFieldClass().func() === PublicFieldClass");
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsNested) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class Outer {"
          "  #odata = 42;"
          "  #inner;"
          "  static getInner() {"
          "    class Inner {"
          "      #idata = 42;"
          "      #outer;"
          "      constructor(outer) {"
          "        this.#outer = outer;"
          "        outer.#inner = this;"
          "      }"
          "      check() {"
          "        return this.#idata === this.#outer.#odata &&"
          "               this === this.#outer.#inner;"
          "      }"
          "    }"
          "    return Inner;"
          "  }"
          "  check() {"
          "    return this.#inner.check();"
          "  }"
          "}"
          "const Inner = Outer.getInner();");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectTrue("(new Inner(new Outer)).check()");
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassPrivateMethods) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class JustPrivateMethods {"
          "  #method() { return this.val; }"
          "  get #accessor() { return this.val; };"
          "  set #accessor(val) { this.val = val; }"
          "  method() { return this.#method(); } "
          "  getter() { return this.#accessor; } "
          "  setter(val) { this.#accessor = val } "
          "}"
          "class PrivateMethodsAndFields {"
          "  #val = 1;"
          "  #method() { return this.#val; }"
          "  get #accessor() { return this.#val; };"
          "  set #accessor(val) { this.#val = val; }"
          "  method() { return this.#method(); } "
          "  getter() { return this.#accessor; } "
          "  setter(val) { this.#accessor = val } "
          "}"
          "class Nested {"
          "  #val = 42;"
          "  static #method(obj) { return obj.#val; }"
          "  getInner() {"
          "    class Inner {"
          "      runEval(obj, str) {"
          "        return eval(str);"
          "      }"
          "    }"
          "    return Inner;"
          "  }"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    CompileRun("const a = new JustPrivateMethods(); a.setter(42);");
    ExpectInt32("a.method()", 42);
    ExpectInt32("a.getter()", 42);
    CompileRun("const b = new PrivateMethodsAndFields(); b.setter(42);");
    ExpectInt32("b.method()", 42);
    ExpectInt32("b.getter()", 42);
    CompileRun("const c = new (new Nested().getInner());");
    ExpectInt32("c.runEval(new Nested(), 'Nested.#method(obj)')", 42);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsWithInheritance) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class Base {"
          "    #a = 'test';"
          "    getA() { return this.#a; }"
          "}"
          "class Derived extends Base {"
          "  #b = 1;"
          "  constructor() {"
          "      super();"
          "      this.#b = this.getA();"
          "  }"
          "  check() {"
          "    return this.#b === this.getA();"
          "  }"
          "}"
          "class DerivedDefaultConstructor extends Base {"
          "  #b = 1;"
          "  check() {"
          "    return this.#b === 1;"
          "  }"
          "}"
          "class NestedSuper extends Base {"
          "  #b = 1;"
          "  constructor() {"
          "    const t = () => {"
          "      super();"
          "    };"
          "    t();"
          "  }"
          "  check() {"
          "    return this.#b === 1;"
          "  }"
          "}"
          "class EvaledSuper extends Base {"
          "  #b = 1;"
          "  constructor() {"
          "    eval('super()');"
          "  }"
          "  check() {"
          "    return this.#b === 1;"
          "  }"
          "}"
          "class NestedEvaledSuper extends Base {"
          "  #b = 1;"
          "  constructor() {"
          "    const t = () => {"
          "      eval('super()');"
          "    };"
          "    t();"
          "  }"
          "  check() {"
          "    return this.#b === 1;"
          "  }"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectBoolean("(new Derived()).check()", true);
    ExpectBoolean("(new DerivedDefaultConstructor()).check()", true);
    ExpectBoolean("(new NestedSuper()).check()", true);
    ExpectBoolean("(new EvaledSuper()).check()", true);
    ExpectBoolean("(new NestedEvaledSuper()).check()", true);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsRecalcPrivateNames) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "let heritageFn;"
          "class Outer {"
          "  #f = 'Outer.#f';"
          "  static Inner = class Inner extends (heritageFn = function () {"
          "               return class Nested {"
          "                 exfil(obj) { return obj.#f; }"
          "                 exfilEval(obj) { return eval('obj.#f'); }"
          "               };"
          "             }) {"
          "               #f = 'Inner.#f';"
          "             };"
          "};");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    CompileRun(
        "const o = new Outer;"
        "const c = new Outer.Inner;"
        "const D = heritageFn();"
        "const d = new D;"
        "let error1;"
        "let error2;");
    ExpectString("d.exfil(o)", "Outer.#f");
    ExpectString("d.exfilEval(o)", "Outer.#f");
    CompileRun("try { d.exfil(c) } catch(e) { error1 = e; }");
    ExpectBoolean("error1 instanceof TypeError", true);
    CompileRun("try { d.exfilEval(c) } catch(e) { error2 = e; }");
    ExpectBoolean("error2 instanceof TypeError", true);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsWithBindings) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "function testVarBinding() {"
          "  function FuncWithVar() {"
          "    this.getPrivate = () => 'test';"
          "  }"
          "  class Derived extends FuncWithVar {"
          "    ['computed'] = FuncWithVar;"
          "    #private = FuncWithVar;"
          "    public = FuncWithVar;"
          "    constructor() {"
          "        super();"
          "        this.#private = this.getPrivate();"
          "    }"
          "    check() {"
          "      return this.#private === this.getPrivate() &&"
          "             this.computed === FuncWithVar &&"
          "             this.public === FuncWithVar;"
          "    }"
          "  }"
          ""
          "  return((new Derived()).check());"
          "}"
          "class ClassWithLet {"
          "    #private = 'test';"
          "    getPrivate() { return this.#private; }"
          "}"
          "function testLetBinding() {"
          "  class Derived extends ClassWithLet {"
          "    ['computed'] = ClassWithLet;"
          "    #private = ClassWithLet;"
          "    public = ClassWithLet;"
          "    constructor() {"
          "        super();"
          "        this.#private = this.getPrivate();"
          "    }"
          "    check() {"
          "      return this.#private === this.getPrivate() &&"
          "             this.computed === ClassWithLet &&"
          "             this.public === ClassWithLet;"
          "    }"
          "  }"
          ""
          "  return((new Derived()).check());"
          "}"
          "const ClassWithConst = class {"
          "    #private = 'test';"
          "    getPrivate() { return this.#private; }"
          "};"
          "function testConstBinding() {"
          "  class Derived extends ClassWithConst {"
### 提示词
```
这是目录为v8/test/cctest/test-serialize.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-serialize.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```
s.add(1);"
          "s.add(globalThis);");
      ExpectInt32("m.get('b')", 2);
      ExpectTrue("s.has(1)");
      ExpectTrue("s.has(globalThis)");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    CHECK(blob.CanBeRehashed());
  }

  i::v8_flags.hash_seed = 1337;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    // Check that rehashing has been performed.
    CHECK_EQ(static_cast<uint64_t>(1337),
             HashSeed(reinterpret_cast<i::Isolate*>(isolate)));
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectInt32("m.get('b')", 2);
    ExpectTrue("s.has(1)");
    ExpectTrue("s.has(globalThis)");
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ReinitializeHashSeedRehashable) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      // Create dictionary mode object.
      CompileRun(
          "var a = new Array(10000);"
          "%NormalizeElements(a);"
          "a[133] = 1;"
          "a[177] = 2;"
          "a[971] = 3;"
          "a[7997] = 4;"
          "a[2111] = 5;"
          "var o = {};"
          "%OptimizeObjectForAddingMultipleProperties(o, 3);"
          "o.a = 1;"
          "o.b = 2;"
          "o.c = 3;"
          "var p = { foo: 1 };"  // Test rehashing of transition arrays.
          "p = JSON.parse('{\"foo\": {\"x\": 1}}');");
      i::Handle<i::Object> i_a = v8::Utils::OpenHandle(*CompileRun("a"));
      i::Handle<i::Object> i_o = v8::Utils::OpenHandle(*CompileRun("o"));
      CHECK(IsJSArray(*i_a));
      CHECK(IsJSObject(*i_a));
      CHECK(!i::Cast<i::JSArray>(i_a)->HasFastElements());
      CHECK(!i::Cast<i::JSObject>(i_o)->HasFastProperties());
      ExpectInt32("a[2111]", 5);
      ExpectInt32("o.c", 3);
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    CHECK(blob.CanBeRehashed());
  }

  i::v8_flags.hash_seed = 1337;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    // Check that rehashing has been performed.
    CHECK_EQ(static_cast<uint64_t>(1337),
             HashSeed(reinterpret_cast<i::Isolate*>(isolate)));
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    i::Handle<i::Object> i_a = v8::Utils::OpenHandle(*CompileRun("a"));
    i::Handle<i::Object> i_o = v8::Utils::OpenHandle(*CompileRun("o"));
    CHECK(IsJSArray(*i_a));
    CHECK(IsJSObject(*i_a));
    CHECK(!i::Cast<i::JSArray>(i_a)->HasFastElements());
    CHECK(!i::Cast<i::JSObject>(i_o)->HasFastProperties());
    ExpectInt32("a[2111]", 5);
    ExpectInt32("o.c", 3);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFields) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class ClassWithFieldInitializer {"
          "  #field = 1;"
          "  constructor(val) {"
          "    this.#field = val;"
          "  }"
          "  get field() {"
          "    return this.#field;"
          "  }"
          "}"
          "class ClassWithDefaultConstructor {"
          "  #field = 42;"
          "  get field() {"
          "    return this.#field;"
          "  }"
          "}"
          "class ClassWithFieldDeclaration {"
          "  #field;"
          "  constructor(val) {"
          "    this.#field = val;"
          "  }"
          "  get field() {"
          "    return this.#field;"
          "  }"
          "}"
          "class ClassWithPublicField {"
          "  field = 1;"
          "  constructor(val) {"
          "    this.field = val;"
          "  }"
          "}"
          "class ClassWithFunctionField {"
          "  field = 123;"
          "  func = () => { return this.field; }"
          "}"
          "class ClassWithThisInInitializer {"
          "  #field = 123;"
          "  field = this.#field;"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectInt32("(new ClassWithFieldInitializer(123)).field", 123);
    ExpectInt32("(new ClassWithDefaultConstructor()).field", 42);
    ExpectInt32("(new ClassWithFieldDeclaration(123)).field", 123);
    ExpectInt32("(new ClassWithPublicField(123)).field", 123);
    ExpectInt32("(new ClassWithFunctionField()).func()", 123);
    ExpectInt32("(new ClassWithThisInInitializer()).field", 123);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsReferencePrivateInInitializer) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class A {"
          "  #a = 42;"
          "  a = this.#a;"
          "}"
          "let str;"
          "class ClassWithEval {"
          "  field = eval(str);"
          "}"
          "class ClassWithPrivateAndEval {"
          "  #field = 42;"
          "  field = eval(str);"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectInt32("(new A()).a", 42);
    v8::TryCatch try_catch(isolate);
    CompileRun("str = 'this.#nonexistent'; (new ClassWithEval()).field");
    CHECK(try_catch.HasCaught());
    try_catch.Reset();
    ExpectInt32("str = 'this.#field'; (new ClassWithPrivateAndEval()).field",
                42);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsReferenceClassVariable) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class PrivateFieldClass {"
          "  #consturctor = PrivateFieldClass;"
          "  func() {"
          "    return this.#consturctor;"
          "  }"
          "}"
          "class PublicFieldClass {"
          "  ctor = PublicFieldClass;"
          "  func() {"
          "    return this.ctor;"
          "  }"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectTrue("new PrivateFieldClass().func() === PrivateFieldClass");
    ExpectTrue("new PublicFieldClass().func() === PublicFieldClass");
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsNested) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class Outer {"
          "  #odata = 42;"
          "  #inner;"
          "  static getInner() {"
          "    class Inner {"
          "      #idata = 42;"
          "      #outer;"
          "      constructor(outer) {"
          "        this.#outer = outer;"
          "        outer.#inner = this;"
          "      }"
          "      check() {"
          "        return this.#idata === this.#outer.#odata &&"
          "               this === this.#outer.#inner;"
          "      }"
          "    }"
          "    return Inner;"
          "  }"
          "  check() {"
          "    return this.#inner.check();"
          "  }"
          "}"
          "const Inner = Outer.getInner();");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectTrue("(new Inner(new Outer)).check()");
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassPrivateMethods) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class JustPrivateMethods {"
          "  #method() { return this.val; }"
          "  get #accessor() { return this.val; };"
          "  set #accessor(val) { this.val = val; }"
          "  method() { return this.#method(); } "
          "  getter() { return this.#accessor; } "
          "  setter(val) { this.#accessor = val } "
          "}"
          "class PrivateMethodsAndFields {"
          "  #val = 1;"
          "  #method() { return this.#val; }"
          "  get #accessor() { return this.#val; };"
          "  set #accessor(val) { this.#val = val; }"
          "  method() { return this.#method(); } "
          "  getter() { return this.#accessor; } "
          "  setter(val) { this.#accessor = val } "
          "}"
          "class Nested {"
          "  #val = 42;"
          "  static #method(obj) { return obj.#val; }"
          "  getInner() {"
          "    class Inner {"
          "      runEval(obj, str) {"
          "        return eval(str);"
          "      }"
          "    }"
          "    return Inner;"
          "  }"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    CompileRun("const a = new JustPrivateMethods(); a.setter(42);");
    ExpectInt32("a.method()", 42);
    ExpectInt32("a.getter()", 42);
    CompileRun("const b = new PrivateMethodsAndFields(); b.setter(42);");
    ExpectInt32("b.method()", 42);
    ExpectInt32("b.getter()", 42);
    CompileRun("const c = new (new Nested().getInner());");
    ExpectInt32("c.runEval(new Nested(), 'Nested.#method(obj)')", 42);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsWithInheritance) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "class Base {"
          "    #a = 'test';"
          "    getA() { return this.#a; }"
          "}"
          "class Derived extends Base {"
          "  #b = 1;"
          "  constructor() {"
          "      super();"
          "      this.#b = this.getA();"
          "  }"
          "  check() {"
          "    return this.#b === this.getA();"
          "  }"
          "}"
          "class DerivedDefaultConstructor extends Base {"
          "  #b = 1;"
          "  check() {"
          "    return this.#b === 1;"
          "  }"
          "}"
          "class NestedSuper extends Base {"
          "  #b = 1;"
          "  constructor() {"
          "    const t = () => {"
          "      super();"
          "    };"
          "    t();"
          "  }"
          "  check() {"
          "    return this.#b === 1;"
          "  }"
          "}"
          "class EvaledSuper extends Base {"
          "  #b = 1;"
          "  constructor() {"
          "    eval('super()');"
          "  }"
          "  check() {"
          "    return this.#b === 1;"
          "  }"
          "}"
          "class NestedEvaledSuper extends Base {"
          "  #b = 1;"
          "  constructor() {"
          "    const t = () => {"
          "      eval('super()');"
          "    };"
          "    t();"
          "  }"
          "  check() {"
          "    return this.#b === 1;"
          "  }"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectBoolean("(new Derived()).check()", true);
    ExpectBoolean("(new DerivedDefaultConstructor()).check()", true);
    ExpectBoolean("(new NestedSuper()).check()", true);
    ExpectBoolean("(new EvaledSuper()).check()", true);
    ExpectBoolean("(new NestedEvaledSuper()).check()", true);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsRecalcPrivateNames) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "let heritageFn;"
          "class Outer {"
          "  #f = 'Outer.#f';"
          "  static Inner = class Inner extends (heritageFn = function () {"
          "               return class Nested {"
          "                 exfil(obj) { return obj.#f; }"
          "                 exfilEval(obj) { return eval('obj.#f'); }"
          "               };"
          "             }) {"
          "               #f = 'Inner.#f';"
          "             };"
          "};");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    CompileRun(
        "const o = new Outer;"
        "const c = new Outer.Inner;"
        "const D = heritageFn();"
        "const d = new D;"
        "let error1;"
        "let error2;");
    ExpectString("d.exfil(o)", "Outer.#f");
    ExpectString("d.exfilEval(o)", "Outer.#f");
    CompileRun("try { d.exfil(c) } catch(e) { error1 = e; }");
    ExpectBoolean("error1 instanceof TypeError", true);
    CompileRun("try { d.exfilEval(c) } catch(e) { error2 = e; }");
    ExpectBoolean("error2 instanceof TypeError", true);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(ClassFieldsWithBindings) {
  DisableAlwaysOpt();
  i::v8_flags.rehash_snapshot = true;
  i::v8_flags.hash_seed = 42;
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "function testVarBinding() {"
          "  function FuncWithVar() {"
          "    this.getPrivate = () => 'test';"
          "  }"
          "  class Derived extends FuncWithVar {"
          "    ['computed'] = FuncWithVar;"
          "    #private = FuncWithVar;"
          "    public = FuncWithVar;"
          "    constructor() {"
          "        super();"
          "        this.#private = this.getPrivate();"
          "    }"
          "    check() {"
          "      return this.#private === this.getPrivate() &&"
          "             this.computed === FuncWithVar &&"
          "             this.public === FuncWithVar;"
          "    }"
          "  }"
          ""
          "  return((new Derived()).check());"
          "}"
          "class ClassWithLet {"
          "    #private = 'test';"
          "    getPrivate() { return this.#private; }"
          "}"
          "function testLetBinding() {"
          "  class Derived extends ClassWithLet {"
          "    ['computed'] = ClassWithLet;"
          "    #private = ClassWithLet;"
          "    public = ClassWithLet;"
          "    constructor() {"
          "        super();"
          "        this.#private = this.getPrivate();"
          "    }"
          "    check() {"
          "      return this.#private === this.getPrivate() &&"
          "             this.computed === ClassWithLet &&"
          "             this.public === ClassWithLet;"
          "    }"
          "  }"
          ""
          "  return((new Derived()).check());"
          "}"
          "const ClassWithConst = class {"
          "    #private = 'test';"
          "    getPrivate() { return this.#private; }"
          "};"
          "function testConstBinding() {"
          "  class Derived extends ClassWithConst {"
          "    ['computed'] = ClassWithConst;"
          "    #private = ClassWithConst;"
          "    public = ClassWithConst;"
          "    constructor() {"
          "        super();"
          "        this.#private = this.getPrivate();"
          "    }"
          "    check() {"
          "      return this.#private === this.getPrivate() &&"
          "             this.computed === ClassWithConst &&"
          "             this.public === ClassWithConst;"
          "    }"
          "  }"
          ""
          "  return((new Derived()).check());"
          "}");
      creator.SetDefaultContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  create_params.snapshot_blob = &blob;
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    CHECK(!context.IsEmpty());
    v8::Context::Scope context_scope(context);
    ExpectBoolean("testVarBinding()", true);
    ExpectBoolean("testLetBinding()", true);
    ExpectBoolean("testConstBinding()", true);
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

void CheckInfosAreWeak(Tagged<WeakFixedArray> sfis, Isolate* isolate) {
  CHECK_GT(sfis->length(), 0);
  int no_of_weak = 0;
  for (int i = 0; i < sfis->length(); ++i) {
    Tagged<MaybeObject> maybe_object = sfis->get(i);
    Tagged<HeapObject> heap_object;
    CHECK(!maybe_object.GetHeapObjectIfWeak(isolate, &heap_object) ||
          (maybe_object.GetHeapObjectIfStrong(&heap_object) &&
           IsUndefined(heap_object, isolate)) ||
          Is<SharedFunctionInfo>(heap_object) || Is<ScopeInfo>(heap_object));
    if (maybe_object.IsWeak()) {
      ++no_of_weak;
    }
  }
  CHECK_GT(no_of_weak, 0);
}

UNINITIALIZED_TEST(WeakArraySerializationInSnapshot) {
  const char* code = "var my_func = function() { }";

  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  i::v8_flags.allow_natives_syntax = true;
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      creator.SetDefaultContext(
          context, v8::SerializeInternalFieldsCallback(
                       SerializeInternalFields, reinterpret_cast<void*>(2016)));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(),
        v8::DeserializeInternalFieldsCallback(DeserializeInternalFields,
                                              reinterpret_cast<void*>(2017)));
    v8::Context::Scope c_scope(context);

    v8::Local<v8::Value> x = CompileRun("my_func");
    CHECK(x->IsFunction());
    DirectHandle<JSFunction> function =
        Cast<JSFunction>(v8::Utils::OpenDirectHandle(*x));

    // Verify that the pointers in infos are weak.
    Tagged<WeakFixedArray> sfis =
        Cast<Script>(function->shared()->script())->infos();
    CheckInfosAreWeak(sfis, reinterpret_cast<i::Isolate*>(isolate));
  }
  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

TEST(WeakArraySerializationInCodeCache) {
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()->DisableScriptAndEval();

  v8::HandleScope scope(CcTest::isolate());

  const char* source = "function foo() { }";

  Handle<String> src = isolate->factory()
                           ->NewStringFromUtf8(base::CStrVector(source))
                           .ToHandleChecked();
  AlignedCachedData* cache = nullptr;

  ScriptDetails script_details(src);
  CompileScriptAndProduceCache(isolate, src, script_details, &cache,
                               v8::ScriptCompiler::kNoCompileOptions);

  DisallowCompilation no_compile_expected(isolate);
  DirectHandle<SharedFunctionInfo> copy =
      CompileScript(isolate, src, script_details, cache,
                    v8::ScriptCompiler::kConsumeCodeCache);

  // Verify that the pointers in infos are weak.
  Tagged<WeakFixedArray> sfis = Cast<Script>(copy->script())->infos();
  CheckInfosAreWeak(sfis, isolate);

  delete cache;
}

v8::MaybeLocal<v8::Promise> TestHostDefinedOptionFromCachedScript(
    Local<v8::Context> context, Local<v8::Data> host_defined_options,
    Local<v8::Value> resource_name, Local<v8::String> specifier,
    Local<v8::FixedArray> import_attributes) {
  CHECK(host_defined_options->IsFixedArray());
  auto arr = host_defined_options.As<v8::FixedArray>();
  CHECK_EQ(arr->Length(), 1);
  v8::Local<v8::Symbol> expected =
      v8::Symbol::For(context->GetIsolate(), v8_str("hdo"));
  CHECK_EQ(arr->Get(context, 0), expected);
  CHECK(resource_name->Equals(context, v8_str("test_hdo")).FromJust());
  CHECK(specifier->Equals(context, v8_str("foo")).FromJust());

  Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context).ToLocalChecked();
  resolver->Resolve(context, v8_str("hello")).ToChecked();
  return resolver->GetPromise();
}

TEST(CachedFunctionHostDefinedOption) {
  DisableAlwaysOpt();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.
  isolate->SetHostImportModuleDynamicallyCallback(
      TestHostDefinedOptionFromCachedScript);

  v8::HandleScope scope(isolate);

  v8::Local<v8::String> source = v8_str("return import(x)");
  v8::Local<v8::String> arg_str = v8_str("x");

  v8::Local<v8::PrimitiveArray> hdo = v8::PrimitiveArray::New(isolate, 1);
  hdo->Set(isolate, 0, v8::Symbol::For(isolate, v8_str("hdo")));
  v8::ScriptOrigin origin(v8_str("test_hdo"),  // resource_name
                          0,                   // resource_line_offset
                          0,                   // resource_column_offset
                          false,  // resource_is_shared_cross_origin
                          -1,     // script_id
                          {},     // source_map_url
                          false,  // resource_is_opaque
                          false,  // is_wasm
                          false,  // is_module
                          hdo     // host_defined_options
  );
  ScriptCompiler::CachedData* cache;
  {
    v8::ScriptCompiler::Source script_source(source, origin);
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(
            env.local(), &script_source, 1, &arg_str, 0, nullptr,
            v8::ScriptCompiler::kNoCompileOptions)
            .ToLocalChecked();
    cache = v8::ScriptCompiler::CreateCodeCacheForFunction(fun);
  }

  {
    DisallowCompilation no_compile_expected(i_isolate);
    v8::ScriptCompiler::Source script_source(source, origin, cache);
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(
            env.local(), &script_source, 1, &arg_str, 0, nullptr,
            v8::ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();
    v8::Local<v8::Value> arg = v8_str("foo");
    v8::Local<v8::Value> result =
        fun->Call(env.local(), v8::Undefined(isolate), 1, &arg)
            .ToLocalChecked();
    CHECK(result->IsPromise());
    v8::Local<v8::Promise> promise = result.As<v8::Promise>();
    isolate->PerformMicrotaskCheckpoint();
    v8::Local<v8::Value> resolved = promise->Result();
    CHECK(resolved->IsString());
    CHECK(resolved.As<v8::String>()
              ->Equals(env.local(), v8_str("hello"))
              .FromJust());
  }
}

TEST(CachedUnboundScriptHostDefinedOption) {
  DisableAlwaysOpt();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.
  isolate->SetHostImportModuleDynamicallyCallback(
      TestHostDefinedOptionFromCachedScript);

  v8::HandleScope scope(isolate);

  v8::Local<v8::String> source = v8_str("globalThis.foo =import('foo')");

  v8::Local<v8::PrimitiveArray> hdo = v8::PrimitiveArray::New(isolate, 1);
  hdo->Set(isolate, 0, v8::Symbol::For(isolate, v8_str("hdo")));
  v8::ScriptOrigin origin(v8_str("test_hdo"),  // resource_name
                          0,                   // resource_line_offset
                          0,                   // resource_column_offset
                          false,  // resource_is_shared_cross_origin
                          -1,     // script_id
                          {},     // source_map_url
                          false,  // resource_is_opaque
                          false,  // is_wasm
                          false,  // is_module
                          hdo     // host_defined_options
  );
  ScriptCompiler::CachedData* cache;
  {
    v8::ScriptCompiler::Source script_source(source, origin);
    v8::Local<v8::UnboundScript> script =
        v8::ScriptCompiler::CompileUnboundScript(
            isolate, &script_source, v8::ScriptCompiler::kNoCompileOptions)
            .ToLocalChecked();
    cache = v8::ScriptCompiler::CreateCodeCache(script);
  }

  {
    DisallowCompilation no_compile_expected(i_isolate);
    v8::ScriptCompiler::Sou
```