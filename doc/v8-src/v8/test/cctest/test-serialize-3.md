Response: The user wants a summary of the C++ code provided, focusing on its functionality and its relation to JavaScript. Since this is the 4th part of a multi-part file, the summary should reflect that.

**Overall Goal:** Understand the testing of the serialization and deserialization mechanism in V8.

**Breakdown of the code:**

The code consists of several `UNINITIALIZED_TEST` and `TEST` functions. These functions generally follow a pattern:

1. **Setup:**  Disable optimizations, set flags (like `rehash_snapshot`, `hash_seed`, `allow_natives_syntax`), and optionally disable embedded blob refcounting.
2. **Snapshot Creation (First Isolate):**
   - Create a `SnapshotCreator`.
   - Create a V8 isolate and context within the creator.
   - Run JavaScript code to set up some state (variables, objects, classes, etc.).
   - Call `creator.SetDefaultContext(context)` to mark the context for snapshotting.
   - Create the snapshot blob using `creator.CreateBlob()`.
3. **Snapshot Deserialization (Second Isolate):**
   - Set flags as needed for deserialization.
   - Create a *new* V8 isolate, providing the created snapshot blob in the `create_params`.
   - Create a context in the new isolate.
   - Run JavaScript code in the deserialized context to verify that the state from the snapshot was correctly restored. This often involves assertions using `ExpectInt32`, `ExpectTrue`, `ExpectBoolean`, etc.
4. **Cleanup:** Dispose of the isolate and free the snapshot blob data.

**Specific Functionalities Demonstrated in Part 4:**

- **Rehashing after deserialization:**  Tests that the hash seed can be changed after a snapshot is created, and that data structures like Maps and Sets are correctly rehashed upon deserialization with the new seed.
- **Serialization and deserialization of JavaScript classes:**  Covers various aspects of class serialization, including:
    - Fields (public and private, with and without initializers).
    - Methods (public and private).
    - Getters and setters (private).
    - Inheritance.
    - Static members.
    - Nested classes.
    - Class expressions.
    - References to class variables and private members within initializers and methods.
    - Computed property names.
    - Bindings of classes to variables (var, let, const).
- **Weak array serialization in snapshots and code cache:** Verifies that weak references in arrays associated with functions (like `ScriptInfos`) are correctly handled during serialization.
- **Code caching (function and unbound script):**  Tests the mechanism for caching compiled JavaScript code and reusing it to speed up subsequent executions. This includes scenarios with host-defined options.
- **Module code caching:** Similar to function and unbound script caching, but specifically for JavaScript modules.
- **Eager vs. lazy compilation with caching:** Checks how the `kEagerCompile` flag affects cached functions.
- **Snapshot creator options (`kKeep`):** Demonstrates the `kKeep` option for snapshot creation, specifically with anonymous classes.
- **Not deferring byte arrays for TypedArrays during snapshot creation:**  Ensures that byte arrays backing TypedArrays are included in the snapshot and not deferred.
- **No stack frame cache serialization:**  Confirms that stack traces from exceptions are not cached in a way that would prevent proper deserialization.
- **Shared strings:**  Tests the behavior when deserializing with the `--shared-string-table` flag, ensuring that strings are shared between isolates.
- **Breakpoints in deserialized contexts:** Verifies that breakpoints set on accessors in a deserialized context are correctly hit in subsequent executions in the same or different contexts created from the same snapshot.
- **Static roots predictability (if the build supports it):** Checks if the generated snapshot is predictable across multiple runs when static roots are enabled.

**Relationship to JavaScript:**

All the tests directly manipulate JavaScript code and data structures within the V8 engine. The C++ code sets up the V8 environment, creates and deserializes snapshots, and then uses the V8 API to execute JavaScript code and verify the results.

**JavaScript Examples (Illustrative):**

Based on the C++ code, here are some simplified JavaScript examples demonstrating the concepts being tested:

- **Rehashing:**

```javascript
// In the snapshot creation phase:
const map = new Map();
map.set('a', 1);
map.set('b', 2);

const set = new Set();
set.add(1);
set.add(globalThis);

// After deserialization with a new hash seed:
console.log(map.get('b')); // Expected output: 2
console.log(set.has(1));   // Expected output: true
console.log(set.has(globalThis)); // Expected output: true
```

- **Class Serialization:**

```javascript
// Class with a private field and method
class MyClass {
  #privateField = 42;
  #privateMethod() { return this.#privateField; }
  getPrivate() { return this.#privateMethod(); }
}

const instance = new MyClass();
console.log(instance.getPrivate()); // Expected output: 42

// After serialization and deserialization, the instance should still work.
```

- **Code Caching:**

```javascript
// First execution (generates the cache):
function add(a, b) { return a + b; }
add(5, 3);

// Subsequent execution (uses the cache):
function add(a, b) { return a + b; } // Same function definition
console.log(add(10, 2)); // Should be faster because the code is cached
```

- **Breakpoints:**

```javascript
// In one deserialized context:
function get value() { return 42; }
debugger; // Breakpoint set here
value;

// In another deserialized context (created from the same snapshot):
value; // Should hit the breakpoint set in the other context (if it's on the accessor's getter)
```
这是 `v8/test/cctest/test-serialize.cc` 文件的第四部分，主要功能是 **测试 V8 引擎的序列化和反序列化机制的各种场景**。由于是最后一部分，它涵盖了更复杂和边缘的情况，并特别关注了与 JavaScript 新特性（如私有类成员）和性能优化（如代码缓存）相关的序列化问题。

具体来说，这部分测试涵盖了以下功能：

**1. 反序列化后重新哈希 (Rehashing):**

* 测试在创建快照后和反序列化时修改哈希种子 (`hash_seed`) 是否会导致 `Map` 和 `Set` 等数据结构正确地重新哈希。这对于安全性至关重要，可以防止某些类型的攻击。

**2. JavaScript 类特性的序列化和反序列化:**

* 深入测试了各种 JavaScript 类特性在序列化和反序列化过程中的表现，包括：
    * **私有字段和方法:**  测试了私有字段 (`#field`)、私有方法 (`#method`)、私有 getter 和 setter 的正确序列化和访问。
    * **继承:** 测试了包含私有成员的类的继承关系在序列化后的行为。
    * **静态成员:**  测试了静态成员在序列化后的保留和访问。
    * **嵌套类:**  测试了嵌套类及其私有成员的序列化。
    * **类表达式:** 测试了作为表达式定义的类的序列化。
    * **在初始化器中引用私有成员和类变量:** 测试了在类字段初始化器中引用 `this` 和类自身的情况。
    * **计算属性名:**  测试了带有计算属性名的类字段的序列化。
    * **类与变量绑定 (var, let, const):** 测试了将类绑定到不同类型变量时的序列化行为。

**3. 弱数组的序列化 (Weak Array Serialization):**

* 测试了在快照和代码缓存中序列化包含弱引用的数组（例如，用于存储脚本信息的数组）时的正确性。这确保了在反序列化后，弱引用仍然是弱引用，并且不会阻止垃圾回收。

**4. 代码缓存 (Code Caching):**

* 测试了 V8 的代码缓存机制在序列化和反序列化场景下的工作情况，包括：
    * **缓存函数:**  测试了编译后的函数代码是否可以被缓存并在反序列化后重用，从而提高性能。
    * **缓存未绑定的脚本:** 测试了未绑定到特定上下文的脚本的代码缓存。
    * **缓存模块脚本函数:** 测试了模块的代码缓存。
    * **使用 Host-Defined Options 的代码缓存:** 测试了带有自定义选项的脚本的代码缓存。
    * **尊重 Eager 编译:** 测试了代码缓存是否尊重提前编译 (`kEagerCompile`) 的设置。

**5. 快照创建器的选项:**

* 测试了 `SnapshotCreator` 的 `FunctionCodeHandling::kKeep` 选项，特别是在匿名类的情况下的行为。

**6. 避免为 TypedArray 延迟 ByteArray:**

* 测试了在创建快照时，`TypedArray` 底层的 `ByteArray` 是否不会被延迟处理，而是直接包含在快照中。

**7. 不序列化堆栈帧缓存 (No Stack Frame Cache Serialization):**

* 测试了在序列化期间捕获的异常的堆栈信息不会被缓存到堆栈帧缓存中，因为这些信息可能包含对需要存储在上下文快照中的 `JSFunction` 对象的引用。

**8. 共享字符串 (Shared Strings):**

* 如果启用了共享堆 (`--shared-string-table`)，则测试反序列化是否会将字符串放入共享的隔离堆中，从而节省内存。

**9. 断点与反序列化的上下文 (BreakPoint Accessor Context Snapshot):**

* 测试在一个反序列化上下文中设置的断点是否会在其他从同一快照创建的上下文中被触发，特别是对于延迟访问器。

**10. 静态根的可预测性 (Static Roots Predictable Snapshot):**

* 在支持静态根的构建中，测试生成的快照是否是可预测的，这对于提高性能和减少内存占用非常重要。

**与 JavaScript 的关系：**

这个 C++ 文件是 V8 引擎测试套件的一部分，其核心目标是验证 V8 如何正确地序列化和反序列化各种 JavaScript 结构和状态。  几乎每个测试都涉及到：

1. **在 C++ 中创建 V8 隔离区和上下文。**
2. **在创建快照之前，在 JavaScript 上下文中运行 JavaScript 代码，创建需要被序列化的对象、类、函数等。**  例如，`CompileRun("var m = new Map(); m.set('b', 2); ...")` 就是在 JavaScript 中创建 `Map` 和 `Set` 对象。
3. **使用 `SnapshotCreator` 将 JavaScript 堆的状态序列化成二进制数据 (blob)。**
4. **创建一个新的 V8 隔离区，并使用之前生成的 blob 进行初始化 (反序列化)。**
5. **在新隔离区的 JavaScript 上下文中运行 JavaScript 代码，来验证反序列化后的状态是否与原始状态一致。** 例如，`ExpectInt32("m.get('b')", 2);` 就是在反序列化后的上下文中检查 `Map` 的内容。

**JavaScript 例子：**

很多测试用例的代码片段本身就是很好的 JavaScript 例子，例如：

```javascript
// 测试私有字段
class ClassWithFieldInitializer {
  #field = 1;
  constructor(val) {
    this.#field = val;
  }
  get field() {
    return this.#field;
  }
}
```

或者代码缓存的例子：

```javascript
function foo() { } // 这段代码会被编译并可能被缓存
```

总而言之，`test-serialize.cc` 的第四部分深入测试了 V8 引擎在序列化和反序列化复杂 JavaScript 特性和优化机制方面的鲁棒性和正确性，确保 V8 能够可靠地保存和恢复 JavaScript 的执行状态，这对于诸如快照启动、代码缓存等重要功能至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-serialize.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
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
    v8::ScriptCompiler::Source script_source(source, origin, cache);
    v8::Local<v8::UnboundScript> script =
        v8::ScriptCompiler::CompileUnboundScript(
            isolate, &script_source, v8::ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();
    v8::Local<v8::Script> bound = script->BindToCurrentContext();
    USE(bound->Run(env.local(), hdo).ToLocalChecked());
    v8::Local<v8::Value> result =
        env.local()->Global()->Get(env.local(), v8_str("foo")).ToLocalChecked();
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

v8::MaybeLocal<v8::Module> UnexpectedModuleResolveCallback(
    v8::Local<v8::Context> context, v8::Local<v8::String> specifier,
    v8::Local<v8::FixedArray> import_attributes,
    v8::Local<v8::Module> referrer) {
  CHECK_WITH_MSG(false, "Unexpected call to resolve callback");
}

TEST(CachedModuleScriptFunctionHostDefinedOption) {
  DisableAlwaysOpt();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i_isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.
  isolate->SetHostImportModuleDynamicallyCallback(
      TestHostDefinedOptionFromCachedScript);

  v8::HandleScope scope(isolate);

  v8::Local<v8::String> source = v8_str("globalThis.foo = import('foo')");

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
                          true,   // is_module
                          hdo     // host_defined_options
  );
  ScriptCompiler::CachedData* cache;
  {
    v8::ScriptCompiler::Source script_source(source, origin);
    v8::Local<v8::Module> mod =
        v8::ScriptCompiler::CompileModule(isolate, &script_source,
                                          v8::ScriptCompiler::kNoCompileOptions)
            .ToLocalChecked();
    cache = v8::ScriptCompiler::CreateCodeCache(mod->GetUnboundModuleScript());
  }

  {
    DisallowCompilation no_compile_expected(i_isolate);
    v8::ScriptCompiler::Source script_source(source, origin, cache);
    v8::Local<v8::Module> mod =
        v8::ScriptCompiler::CompileModule(isolate, &script_source,
                                          v8::ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();
    mod->InstantiateModule(env.local(), UnexpectedModuleResolveCallback)
        .Check();
    v8::Local<v8::Value> evaluted = mod->Evaluate(env.local()).ToLocalChecked();
    CHECK(evaluted->IsPromise());
    CHECK_EQ(evaluted.As<v8::Promise>()->State(),
             v8::Promise::PromiseState::kFulfilled);
    v8::Local<v8::Value> result =
        env.local()->Global()->Get(env.local(), v8_str("foo")).ToLocalChecked();
    v8::Local<v8::Promise> promise = result.As<v8::Promise>();
    isolate->PerformMicrotaskCheckpoint();
    v8::Local<v8::Value> resolved = promise->Result();
    CHECK(resolved->IsString());
    CHECK(resolved.As<v8::String>()
              ->Equals(env.local(), v8_str("hello"))
              .FromJust());
  }
}

TEST(CachedCompileFunction) {
  DisableAlwaysOpt();
  LocalContext env;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::String> source = v8_str("return x*x;");
  v8::Local<v8::String> arg_str = v8_str("x");
  ScriptCompiler::CachedData* cache;
  {
    v8::ScriptCompiler::Source script_source(source);
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(env.local(), &script_source, 1,
                                            &arg_str, 0, nullptr,
                                            v8::ScriptCompiler::kEagerCompile)
            .ToLocalChecked();
    cache = v8::ScriptCompiler::CreateCodeCacheForFunction(fun);
  }

  {
    DisallowCompilation no_compile_expected(isolate);
    v8::ScriptCompiler::Source script_source(source, cache);
    v8::Local<v8::Function> fun =
        v8::ScriptCompiler::CompileFunction(
            env.local(), &script_source, 1, &arg_str, 0, nullptr,
            v8::ScriptCompiler::kConsumeCodeCache)
            .ToLocalChecked();
    v8::Local<v8::Value> arg = v8_num(3);
    v8::Local<v8::Value> result =
        fun->Call(env.local(), v8::Undefined(CcTest::isolate()), 1, &arg)
            .ToLocalChecked();
    CHECK_EQ(9, result->Int32Value(env.local()).FromJust());
  }
}

TEST(CachedCompileFunctionRespectsEager) {
  DisableAlwaysOpt();
  LocalContext env;
  Isolate* isolate = CcTest::i_isolate();
  isolate->compilation_cache()
      ->DisableScriptAndEval();  // Disable same-isolate code cache.

  v8::HandleScope scope(CcTest::isolate());

  v8::Local<v8::String> source = v8_str("return function() { return 42; }");
  v8::ScriptCompiler::Source script_source(source);

  for (bool eager_compile : {false, true}) {
    v8::ScriptCompiler::CompileOptions options =
        eager_compile ? v8::ScriptCompiler::kEagerCompile
                      : v8::ScriptCompiler::kNoCompileOptions;
    v8::Local<v8::Value> fun =
        v8::ScriptCompiler::CompileFunction(env.local(), &script_source, 0,
                                            nullptr, 0, nullptr, options)
            .ToLocalChecked()
            .As<v8::Function>()
            ->Call(env.local(), v8::Undefined(CcTest::isolate()), 0, nullptr)
            .ToLocalChecked();

    auto i_fun = i::Cast<i::JSFunction>(Utils::OpenHandle(*fun));

    // Function should be compiled iff kEagerCompile was used.
    CHECK_EQ(i_fun->shared()->is_compiled(), eager_compile);
  }
}

UNINITIALIZED_TEST(SnapshotCreatorAnonClassWithKeep) {
  DisableAlwaysOpt();
  SnapshotCreatorParams testing_params;
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  {
    v8::HandleScope handle_scope(isolate);
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CompileRun(
          "function Foo() { return class {}; } \n"
          "class Bar extends Foo() {}\n"
          "Foo()\n");
      creator.SetDefaultContext(context);
    }
  }
  v8::StartupData blob =
      creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kKeep);

  delete[] blob.data;
}

UNINITIALIZED_TEST(SnapshotCreatorDontDeferByteArrayForTypedArray) {
  DisableAlwaysOpt();
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
          "const z = new Uint8Array(1);\n"
          "class A { \n"
          "  static x() { \n"
          "  } \n"
          "} \n"
          "class B extends A {} \n"
          "B.foo = ''; \n"
          "class C extends B {} \n"
          "class D extends C {} \n"
          "class E extends B {} \n"
          "function F() {} \n"
          "Object.setPrototypeOf(F, D); \n");
      creator.SetDefaultContext(context);
    }

    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
    CHECK(blob.raw_size > 0 && blob.data != nullptr);
  }
  {
    SnapshotCreatorParams testing_params(nullptr, &blob);
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    v8::HandleScope scope(isolate);
    USE(v8::Context::New(isolate));
  }
  delete[] blob.data;
}

class V8_NODISCARD DisableLazySourcePositionScope {
 public:
  DisableLazySourcePositionScope()
      : backup_value_(v8_flags.enable_lazy_source_positions) {
    v8_flags.enable_lazy_source_positions = false;
  }
  ~DisableLazySourcePositionScope() {
    v8_flags.enable_lazy_source_positions = backup_value_;
  }

 private:
  bool backup_value_;
};

UNINITIALIZED_TEST(NoStackFrameCacheSerialization) {
  // Checks that exceptions caught are not cached in the
  // stack frame cache during serialization. The individual frames
  // can point to JSFunction objects, which need to be stored in a
  // context snapshot, *not* isolate snapshot.
  DisableAlwaysOpt();
  DisableLazySourcePositionScope lazy_scope;

  SnapshotCreatorParams testing_params;
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  isolate->SetCaptureStackTraceForUncaughtExceptions(true);
  {
    v8::HandleScope handle_scope(isolate);
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::TryCatch try_catch(isolate);
      CompileRun(R"(
        function foo() { throw new Error('bar'); }
        function bar() {
          foo();
        }
        bar();
      )");

      creator.SetDefaultContext(context);
    }
  }
  v8::StartupData blob =
      creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kKeep);

  delete[] blob.data;
}

namespace {
void CheckObjectsAreInSharedHeap(Isolate* isolate) {
  Heap* heap = isolate->heap();
  HeapObjectIterator iterator(heap);
  DisallowGarbageCollection no_gc;
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    const bool expected_in_shared_old =
        heap->MustBeInSharedOldSpace(obj) ||
        (IsString(obj) && String::IsInPlaceInternalizable(Cast<String>(obj)));
    if (expected_in_shared_old) {
      CHECK(HeapLayout::InAnySharedSpace(obj));
    }
  }
}
}  // namespace

UNINITIALIZED_TEST(SharedStrings) {
  // Test that deserializing with --shared-string-table deserializes into the
  // shared Isolate.

  if (!V8_CAN_CREATE_SHARED_HEAP_BOOL) return;
  // In multi-cage mode we create one cage per isolate
  // and we don't share objects between cages.
  if (COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL) return;

  // Make all the flags that require a shared heap false before creating the
  // isolate to serialize.
  v8_flags.shared_string_table = false;
  v8_flags.harmony_struct = false;

  v8::Isolate* isolate_to_serialize = TestSerializer::NewIsolateInitialized();
  StartupBlobs blobs = Serialize(isolate_to_serialize);
  isolate_to_serialize->Dispose();

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  v8::Isolate* isolate1 = TestSerializer::NewIsolateFromBlob(blobs);
  v8::Isolate* isolate2 = TestSerializer::NewIsolateFromBlob(blobs);
  Isolate* i_isolate1 = reinterpret_cast<Isolate*>(isolate1);
  Isolate* i_isolate2 = reinterpret_cast<Isolate*>(isolate2);

  CHECK_EQ(i_isolate1->string_table(), i_isolate2->string_table());
  i_isolate2->main_thread_local_heap()->ExecuteMainThreadWhileParked(
      [i_isolate1]() { CheckObjectsAreInSharedHeap(i_isolate1); });

  i_isolate1->main_thread_local_heap()->ExecuteMainThreadWhileParked(
      [i_isolate2]() { CheckObjectsAreInSharedHeap(i_isolate2); });

  // Because both isolate1 and isolate2 are considered running on the main
  // thread, one must be parked to avoid deadlock in the shared heap
  // verification that may happen on client heap disposal.
  i_isolate1->main_thread_local_heap()->ExecuteMainThreadWhileParked(
      [isolate2]() { isolate2->Dispose(); });
  isolate1->Dispose();

  blobs.Dispose();
  FreeCurrentEmbeddedBlob();
}

namespace {

class DebugBreakCounter : public v8::debug::DebugDelegate {
 public:
  void BreakProgramRequested(v8::Local<v8::Context>,
                             const std::vector<v8::debug::BreakpointId>&,
                             v8::debug::BreakReasons break_reasons) override {
    break_point_hit_count_++;
  }

  int break_point_hit_count() const { return break_point_hit_count_; }

 private:
  int break_point_hit_count_ = 0;
};

}  // namespace

UNINITIALIZED_TEST(BreakPointAccessorContextSnapshot) {
  // Tests that a breakpoint set in one deserialized context also gets hit in
  // another for lazy accessors.
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;

  {
    SnapshotCreatorParams testing_params(original_external_references);
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      // Add a context to the snapshot that adds an object with an accessor to
      // the global template.
      v8::HandleScope scope(isolate);

      auto accessor_tmpl =
          v8::FunctionTemplate::New(isolate, SerializedCallback);
      accessor_tmpl->SetClassName(v8_str("get f"));
      auto object_tmpl = v8::ObjectTemplate::New(isolate);
      object_tmpl->SetAccessorProperty(v8_str("f"), accessor_tmpl);

      auto global_tmpl = v8::ObjectTemplate::New(isolate);
      global_tmpl->Set(v8_str("o"), object_tmpl);

      creator.SetDefaultContext(v8::Context::New(isolate));

      v8::Local<v8::Context> context =
          v8::Context::New(isolate, nullptr, global_tmpl);
      creator.AddContext(context);
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &blob;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();
  params.external_references = original_external_references;
  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope isolate_scope(isolate);

    DebugBreakCounter delegate;
    v8::debug::SetDebugDelegate(isolate, &delegate);

    {
      // Create a new context from the snapshot, put a breakpoint on the
      // accessor and make sure we hit the breakpoint.
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context =
          v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();
      v8::Context::Scope context_scope(context);

      // 1. Set the breakpoint
      v8::Local<v8::Function> function =
          CompileRun(context, "Object.getOwnPropertyDescriptor(o, 'f').get")
              .ToLocalChecked()
              .As<v8::Function>();
      debug::BreakpointId id;
      debug::SetFunctionBreakpoint(function, v8::Local<v8::String>(), &id);

      // 2. Run and check that we hit the breakpoint
      CompileRun(context, "o.f");
      CHECK_EQ(1, delegate.break_point_hit_count());
    }

    {
      // Create a second context from the snapshot and make sure we still hit
      // the breakpoint without setting it again.
      v8::HandleScope scope(isolate);
      v8::Local<v8::Context> context =
          v8::Context::FromSnapshot(isolate, 0).ToLocalChecked();
      v8::Context::Scope context_scope(context);

      CompileRun(context, "o.f");
      CHECK_EQ(2, delegate.break_point_hit_count());
    }

    v8::debug::SetDebugDelegate(isolate, nullptr);
  }

  isolate->Dispose();
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

// These two flags are preconditions for static roots to work. We don't check
// for V8_STATIC_ROOTS_BOOL since the test targets mksnapshot built without
// static roots, to be able to generate the static-roots.h file.
#if defined(V8_COMPRESS_POINTERS_IN_SHARED_CAGE) && defined(V8_SHARED_RO_HEAP)
UNINITIALIZED_TEST(StaticRootsPredictableSnapshot) {
#ifdef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
  // TODO(jgruber): Snapshot determinism requires predictable heap layout
  // (v8_flags.predictable), but this flag is currently known not to work with
  // CSS due to false positives.
  UNREACHABLE();
#else
  if (v8_flags.random_seed == 0) return;
  const int random_seed = v8_flags.random_seed;

  // Predictable RO promotion order requires a predictable initial heap layout.
  v8_flags.predictable = true;
  // Emulate v8_enable_fast_mksnapshot to speed up this test.
  {
    v8_flags.turbo_verify_allocation = false;
#if defined(V8_TARGET_ARCH_X64) || defined(V8_TARGET_ARCH_IA32)
    v8_flags.turbo_rewrite_far_jumps = false;
#endif
#ifdef ENABLE_SLOW_DCHECKS
    v8_flags.enable_slow_asserts = false;
#endif
  }
  i::FlagList::EnforceFlagImplications();

  v8::Isolate* isolate1 = TestSerializer::NewIsolateInitialized();
  StartupBlobs blobs1 = Serialize(isolate1);
  isolate1->Dispose();

  // Reset the seed.
  v8_flags.random_seed = random_seed;

  v8::Isolate* isolate2 = TestSerializer::NewIsolateInitialized();
  StartupBlobs blobs2 = Serialize(isolate2);
  isolate2->Dispose();

  // We want to ensure that setup-heap-internal.cc creates a predictable heap.
  // For static roots it would be sufficient to check that the root pointers
  // relative to the cage base are identical. However, we can't test this, since
  // when we create two isolates in the same process, the offsets will actually
  // be different.
  CHECK_EQ(blobs1.read_only, blobs2.read_only);

  blobs1.Dispose();
  blobs2.Dispose();
  FreeCurrentEmbeddedBlob();
#endif  // V8_ENABLE_CONSERVATIVE_STACK_SCANNING
}
#endif  // defined(V8_COMPRESS_POINTERS_IN_SHARED_CAGE) &&
        // defined(V8_SHARED_RO_HEAP)

}  // namespace internal
}  // namespace v8

"""


```