Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's test suite (`v8/test/cctest/test-api.cc`).

Here's a breakdown of how to approach this:

1. **Identify the core purpose of the code:**  The file name `test-api.cc` strongly suggests this code tests various aspects of the V8 API.

2. **Analyze individual test cases:**  Each `TEST(...)` block represents a distinct test scenario. Examine the setup and assertions within each test to understand what API feature is being tested.

3. **Look for keywords and patterns:**  Terms like `IsCodeLike`, `eval`, `Function`, `MicrotaskQueue`, `SharedArrayBuffer`, `DeepFreeze`, and `ContinuationPreservedEmbedderData` indicate specific V8 features being tested.

4. **Relate tests to JavaScript functionality:**  If a test seems related to a JavaScript feature (like `eval` or `Function`), provide a JavaScript example to illustrate its behavior.

5. **Infer code logic and potential errors:** For tests involving more complex logic (like the `CodeLike` tests or `DeepFreeze`), try to deduce the expected inputs and outputs and common mistakes a developer might make.

6. **Check for file extension significance:** Note the user's question about `.tq` files. Since this file is `.cc`, it's C++, not Torque.

7. **Consider the "part X of Y" information:** Recognize that this is part of a larger series of tests and aim to summarize the specific functionality covered in this section.

8. **Structure the output:** Organize the findings clearly, addressing each of the user's requests.

**Detailed analysis of each test case:**

* **`SetupCodeLike` helper function:** This function seems to create object templates with a specific `is_code_like` property. This is likely related to how V8 handles strings that should be evaluated as code.

* **`TEST(CodeLikeEval)`:** Tests the behavior of objects marked as "code-like" when used with `eval()`. It verifies that `eval()` treats them differently from regular objects, always evaluating their string representation. It also tests the `SetModifyCodeGenerationFromStringsCallback` API, which allows modifying or disallowing code generation from strings.

* **`TEST(CodeLikeFunction)`:** Similar to `CodeLikeEval`, but tests the behavior when using `new Function()`.

* **`THREADED_TEST(MicrotaskQueueOfContext)` and `THREADED_TEST(SetMicrotaskQueueOfContext)`:**  These tests check the API for getting and setting the microtask queue associated with a V8 context.

* **`TEST(TestSetSabConstructorEnabledCallback)`:** Tests the `SetSharedArrayBufferConstructorEnabledCallback` API, which allows embedding code to control whether the `SharedArrayBuffer` constructor is enabled in a given context.

* **`TEST(EmbedderInstanceTypes)`:** Tests the experimental feature for embedders to define their own instance types for JavaScript objects.

* **`UNINITIALIZED_TEST(IsolateCreateParamsIsMovableAndCopyable)`, `UNINITIALIZED_TEST(OOMDetailsAreMovableAndCopyable)`, `UNINITIALIZED_TEST(JitCodeEventIsMovableAndCopyable)`:** These tests ensure that certain V8 API structures can be correctly copied and moved, which is important for performance and memory management.

* **`TEST(WasmAbortStreamingAfterContextDisposal)`:** This test (only present if WebAssembly is enabled) verifies that aborting a WebAssembly streaming compilation after the context is disposed of doesn't lead to issues.

* **`TEST(DeepFreezeIncompatibleTypes)`:** Tests the `DeepFreeze` API, which aims to recursively freeze objects. This test specifically focuses on cases where `DeepFreeze` should throw an error due to incompatible types or non-constant values.

* **`TEST(DeepFreezeIsFrozen)`:**  Further tests the `DeepFreeze` API, checking scenarios where objects should remain modifiable despite being part of a `DeepFreeze` operation (likely due to closures or other indirect references). It also covers cases where freezing should lead to errors.

* **`TEST(DeepFreezeAllowsSyntax)`:** Tests that `DeepFreeze` doesn't prevent the use of valid JavaScript syntax.

* **`TEST(DeepFreezesJSApiObjectWithDelegate)`:** Tests the `DeepFreeze` API's interaction with JavaScript API objects when a `DeepFreezeDelegate` is provided. This delegate allows custom handling of how embedder objects are frozen.

* **`TEST(DeepFreezeDoesntFreezeJSApiObjectFunctionData)`:** Tests that `DeepFreeze` with a delegate doesn't automatically freeze data associated with JavaScript API object functions.

* **`TEST(DeepFreezeForbidsJSApiObjectWithoutDelegate)`:** Tests that `DeepFreeze` throws an error if it encounters a JavaScript API object with internal fields and no delegate is provided.

* **`TEST(DeepFreezeFreezesJSApiObjectData)`:**  Tests that `DeepFreeze` with a delegate can successfully freeze the data associated with JavaScript API objects.

* **`TEST(DeepFreezeFreezesExternalObjectData)`:** Similar to the previous test, but focuses on external objects.

* **`TEST(DeepFreezeInstantiatesAccessors)` and `TEST(DeepFreezeInstantiatesAccessors2)`:** These tests verify that `DeepFreeze` correctly handles accessors (getters and setters) on objects and function templates.

* **`TEST(ContinuationPreservedEmbedderData)`:** Tests the `ContinuationPreservedEmbedderData` API, which allows embedding code to preserve data across promise continuations.

* **`TEST(ContinuationPreservedEmbedderDataCle)`:**  This test is cut off, but likely tests the cleanup or behavior of `ContinuationPreservedEmbedderData`.

By combining the understanding of individual tests, we can form a comprehensive summary of the file's functionality.
`v8/test/cctest/test-api.cc` 是 V8 源代码的一部分，它是一个 C++ 文件，专门用于测试 V8 JavaScript 引擎的 **C++ API** 的各种功能。以下是该文件中各个测试用例的功能归纳：

**主要功能领域:**

1. **Code-like Objects和 `eval`/`new Function` 的交互:**
   - **功能:** 测试 V8 中 "code-like" 对象的概念。这些对象拥有特殊的属性，当它们被转换为字符串并传递给 `eval()` 或 `new Function()` 时，V8 会将它们的内容直接视为代码执行，而不是简单地作为字符串。
   - **JavaScript 例子:**
     ```javascript
     let codeLike = { toString: () => "2 + 2" };
     codeLike.__isCodeLike = true; // 假设的标记方法，实际 V8 API 使用 SetCodeLike()
     console.log(eval(codeLike)); // 输出 4
     console.log(new Function(codeLike)()); // 输出 4
     ```
   - **代码逻辑推理 (CodeLikeEval):**
     - **假设输入:** 创建两个对象，一个标记为 `is_code_like = true`，另一个为 `false`，它们的 `toString` 方法都返回 `"2+2"`。
     - **预期输出:**
       - `eval(new CodeLike())` 返回 `4`。
       - `eval(new Other())` 返回字符串 `"2+2"`。
       - `eval("" + new CodeLike())` 返回 `4`。
       - `eval("" + new Other())` 返回 `4` (因为字符串拼接会触发求值)。
   - **用户常见编程错误:**  不理解 "code-like" 对象的行为，错误地期望它们始终作为字符串处理，或者忘记设置 `SetCodeLike()` 标记。

2. **`SetModifyCodeGenerationFromStringsCallback` 的测试:**
   - **功能:** 测试 V8 允许嵌入器设置回调函数，以修改或阻止从字符串生成代码的功能。这会影响 `eval()` 和 `new Function()` 的行为。
   - **JavaScript 例子:**  这个 API 是 C++ 层的，直接的 JavaScript 例子不太适用。但可以想象，如果回调函数总是返回 `"1+1"`，那么无论传入什么字符串，`eval()` 都会执行 `1+1`。
   - **代码逻辑推理 (涉及 `SetModifyCodeGenerationFromStringsCallback` 的测试):**
     - **假设输入:** 设置不同的回调函数，分别返回固定的替换字符串、总是返回不允许执行的指示，以及只允许 "code-like" 对象执行。
     - **预期输出:**  `eval()` 和 `new Function()` 的结果会根据回调函数的行为而变化，要么执行替换后的代码，要么执行失败。
   - **用户常见编程错误:**  错误地假设 `eval()` 或 `new Function()` 的行为是不可更改的。

3. **Context 的 Microtask Queue 管理:**
   - **功能:** 测试 V8 中与 Context 关联的微任务队列的获取和设置 API。
   - **JavaScript 例子:**
     ```javascript
     queueMicrotask(() => console.log("Microtask executed"));
     Promise.resolve().then(() => console.log("Promise resolved"));
     ```
     这些 JavaScript API 内部会使用 V8 的微任务队列。
   - **代码逻辑推理:** 创建一个 Context，获取其默认的微任务队列，然后设置一个新的微任务队列，并验证获取到的队列是否是新设置的。

4. **`SetSharedArrayBufferConstructorEnabledCallback` 的测试:**
   - **功能:** 测试 V8 允许嵌入器设置回调函数来控制是否启用 `SharedArrayBuffer` 构造函数的功能，可以基于 Context 进行控制。
   - **JavaScript 例子:**
     ```javascript
     // 根据回调函数的设置，以下代码可能会抛出 ReferenceError
     const sab = new SharedArrayBuffer(1024);
     ```
   - **代码逻辑推理:**  设置不同的回调函数，分别返回 `true` 和 `false`，并结合全局的 `enable_sharedarraybuffer_per_context` 标志，验证 `IsSharedArrayBufferConstructorEnabled` 的返回值。

5. **Embedder Instance Types (实验性功能):**
   - **功能:** 测试 V8 的实验性功能，允许嵌入器为 JavaScript 对象定义自定义的实例类型。
   - **JavaScript 例子:** 无法直接用标准 JavaScript 展示，因为这是 V8 内部的扩展机制。
   - **代码逻辑推理:**  创建具有不同嵌入器定义实例类型的对象，并验证其类型信息是否正确。

6. **可移动和可复制的 API 类型:**
   - **功能:** 测试 V8 API 中一些重要类型（如 `Isolate::CreateParams`, `OOMDetails`, `JitCodeEvent`) 是否可以正确地进行拷贝和移动操作，这对于性能和资源管理很重要。

7. **WebAssembly Streaming 中止 (如果启用 WebAssembly):**
   - **功能:** 测试在 Context 被销毁后中止 WebAssembly 流式编译是否能够正常工作，防止资源泄漏或崩溃。

8. **`DeepFreeze` API 的测试:**
   - **功能:**  测试 V8 的 `DeepFreeze` API，它可以递归地冻结对象及其所有属性，使其不可修改。
   - **JavaScript 例子:**
     ```javascript
     const obj = { a: 1, b: { c: 2 } };
     Object.deepFreeze(obj); // 假设有 Object.deepFreeze
     obj.a = 3; // 严格模式下会报错，非严格模式下修改无效
     obj.b.c = 4; // 严格模式下会报错，非严格模式下修改无效
     ```
   - **`DeepFreezeIncompatibleTypes`:** 测试 `DeepFreeze` 在遇到无法冻结的类型（例如，生成器对象、非 const 变量）时是否会抛出错误。
   - **`DeepFreezeIsFrozen`:** 测试 `DeepFreeze` 是否能够正确地冻结对象，以及在冻结后尝试修改对象是否会抛出错误或修改失败。
   - **`DeepFreezeAllowsSyntax`:** 测试 `DeepFreeze` 不会阻止合法的 JavaScript 语法。
   - **`DeepFreezesJSApiObjectWithDelegate`:** 测试 `DeepFreeze` 与嵌入器创建的 JavaScript API 对象的交互，特别是当提供了 `DeepFreezeDelegate` 时，允许嵌入器自定义冻结行为。
   - **`DeepFreezeDoesntFreezeJSApiObjectFunctionData`:** 测试 `DeepFreeze` 不会冻结 JavaScript API 对象函数关联的数据，除非通过 `DeepFreezeDelegate` 特别处理。
   - **`DeepFreezeForbidsJSApiObjectWithoutDelegate`:** 测试当尝试冻结具有内部字段的 JavaScript API 对象但没有提供 `DeepFreezeDelegate` 时，`DeepFreeze` 是否会抛出错误。
   - **`DeepFreezeFreezesJSApiObjectData` 和 `DeepFreezeFreezesExternalObjectData`:** 测试 `DeepFreeze` 配合 `DeepFreezeDelegate` 是否能够正确冻结 JavaScript API 对象和外部对象的数据。
   - **`DeepFreezeInstantiatesAccessors` 和 `DeepFreezeInstantiatesAccessors2`:** 测试 `DeepFreeze` 如何处理对象上的访问器属性（getter/setter）。

9. **Continuation Preserved Embedder Data:**
   - **功能:** 测试 V8 的功能，允许嵌入器在 Promise 的 `then` 方法执行期间保存和恢复嵌入器特定的数据。
   - **JavaScript 例子:** 涉及到 Promise 和 V8 的 C++ API，JavaScript 例子不容易直接展示。
   - **代码逻辑推理:**  设置一些嵌入器数据，创建一个 Promise，并在其 `then` 回调中获取这些数据，验证数据是否被正确地保存和恢复。

**关于 `.tq` 结尾的文件:**

你提到如果文件以 `.tq` 结尾，它将是 V8 Torque 源代码。**这是正确的**。 Torque 是一种 V8 使用的类型化汇编语言，用于实现 JavaScript 的内置功能。由于 `v8/test/cctest/test-api.cc` 的结尾是 `.cc`，所以它是一个 **C++ 源代码文件**，而不是 Torque 文件。

**归纳一下它的功能 (作为第 35 部分):**

作为第 35 部分，这个文件专注于测试 V8 C++ API 的以下几个关键方面，这些方面对于 V8 的嵌入式使用和与宿主环境的交互至关重要：

* **增强的 `eval` 和 `new Function` 控制:**  测试了 V8 如何允许控制字符串到代码的转换，包括 "code-like" 对象的概念和修改代码生成的回调机制。
* **Context 生命周期管理:**  测试了与 Context 相关的微任务队列管理和 `SharedArrayBuffer` 的启用控制。
* **嵌入器扩展机制:**  测试了嵌入器自定义对象类型和 `DeepFreeze` API 的嵌入器委托功能。
* **API 的健壮性和正确性:**  测试了关键 API 类型是否可以安全地拷贝和移动，以及在特定场景下（如 WebAssembly 流式编译中止）的正确行为。
* **对象冻结机制:**  对 `DeepFreeze` API 进行了全面的测试，涵盖了各种类型、场景和与嵌入器对象的交互。
* **跨异步操作的数据传递:** 测试了在 Promise 链中保留嵌入器数据的机制。

总的来说，这个文件深入测试了 V8 API 中与代码执行控制、Context 管理、嵌入器扩展和对象冻结相关的复杂功能，确保这些 API 的正确性和稳定性，这对于将 V8 集成到各种应用程序和环境中至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第35部分，共36部分，请归纳一下它的功能

"""
or + object template for testing IsCodeLike.
  v8::Local<FunctionTemplate> constructor =
      v8::FunctionTemplate::New((*env)->GetIsolate());
  constructor->SetClassName(v8_str(name));
  constructor->InstanceTemplate()->Set((*env)->GetIsolate(), "toString",
                                       to_string);
  if (is_code_like) {
    constructor->InstanceTemplate()->SetCodeLike();
  }
  CHECK_EQ(is_code_like, constructor->InstanceTemplate()->IsCodeLike());
  CHECK((*env)
            ->Global()
            ->Set(env->local(), v8_str(name),
                  constructor->GetFunction(env->local()).ToLocalChecked())
            .FromJust());
}

TEST(CodeLikeEval) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Setup two object templates with an eval-able string representation.
  // One code-like, one not, and otherwise identical.
  auto string_fn = v8::FunctionTemplate::New(
      isolate, [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        CHECK(i::ValidateCallbackInfo(info));
        info.GetReturnValue().Set(v8_str("2+2"));
      });
  SetupCodeLike(&env, "CodeLike", string_fn, true);
  SetupCodeLike(&env, "Other", string_fn, false);

  // Check v8::Object::IsCodeLike.
  CHECK(CompileRun("new CodeLike()").As<v8::Object>()->IsCodeLike(isolate));
  CHECK(!CompileRun("new Other()").As<v8::Object>()->IsCodeLike(isolate));

  // Expected behaviour for normal objects:
  // - eval returns them as-is
  // - when pre-stringified, the string gets evaluated (of course)
  ExpectString("eval(new Other()) + \"\"", "2+2");
  ExpectInt32("eval(\"\" + new Other())", 4);

  // Expected behaviour for 'code like': Is always evaluated.
  ExpectInt32("eval(new CodeLike())", 4);
  ExpectInt32("eval(\"\" + new CodeLike())", 4);

  // Modify callback will always returns a replacement string:
  // Expected behaviour: Always execute the replacement string.
  isolate->SetModifyCodeGenerationFromStringsCallback(
      [](v8::Local<v8::Context> context, v8::Local<v8::Value> source,
         bool is_code_like) -> v8::ModifyCodeGenerationFromStringsResult {
        return {true, v8_str("3+3")};
      });
  ExpectInt32("eval(new Other())", 6);
  ExpectInt32("eval(new CodeLike())", 6);

  // Modify callback always disallows:
  // Expected behaviour: Always fail to execute.
  isolate->SetModifyCodeGenerationFromStringsCallback(
      [](v8::Local<v8::Context> context, v8::Local<v8::Value> source,
         bool is_code_like) -> v8::ModifyCodeGenerationFromStringsResult {
        return {false, v8::Local<v8::String>()};
      });
  CHECK(CompileRun("eval(new Other())").IsEmpty());
  CHECK(CompileRun("eval(new CodeLike())").IsEmpty());

  // Modify callback allows only "code like":
  // Expected behaviour: Only code-like executed, with replacement string.
  isolate->SetModifyCodeGenerationFromStringsCallback(
      [](v8::Local<v8::Context> context, v8::Local<v8::Value> source,
         bool is_code_like) -> v8::ModifyCodeGenerationFromStringsResult {
        bool ok = is_code_like ||
                  (source->IsObject() &&
                   source.As<v8::Object>()->IsCodeLike(context->GetIsolate()));
        return {ok, v8_str("5+7")};
      });
  CHECK(CompileRun("eval(new Other())").IsEmpty());
  ExpectInt32("eval(new CodeLike())", 12);
}

TEST(CodeLikeFunction) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // These follow the pattern of the CodeLikeEval test above, but with
  // "new Function" instead of eval.

  // Setup two object templates with an eval-able string representation.
  // One code kind, one not, and otherwise identical.
  auto string_fn = v8::FunctionTemplate::New(
      isolate, [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        CHECK(i::ValidateCallbackInfo(info));
        info.GetReturnValue().Set(v8_str("return 2+2"));
      });
  SetupCodeLike(&env, "CodeLike", string_fn, true);
  SetupCodeLike(&env, "Other", string_fn, false);

  ExpectInt32("new Function(new Other())()", 4);
  ExpectInt32("new Function(new CodeLike())()", 4);

  // Modify callback will always return a replacement string:
  env.local()->AllowCodeGenerationFromStrings(false);
  isolate->SetModifyCodeGenerationFromStringsCallback(
      [](v8::Local<v8::Context> context, v8::Local<v8::Value> source,
         bool is_code_like) -> v8::ModifyCodeGenerationFromStringsResult {
        return {true, v8_str("(function anonymous(\n) {\nreturn 7;\n})\n")};
      });
  ExpectInt32("new Function(new Other())()", 7);
  ExpectInt32("new Function(new CodeLike())()", 7);

  // Modify callback always disallows:
  isolate->SetModifyCodeGenerationFromStringsCallback(
      [](v8::Local<v8::Context> context, v8::Local<v8::Value> source,
         bool is_code_like) -> v8::ModifyCodeGenerationFromStringsResult {
        return {false, v8::Local<v8::String>()};
      });
  CHECK(CompileRun("new Function(new Other())()").IsEmpty());
  CHECK(CompileRun("new Function(new CodeLike())()").IsEmpty());

  // Modify callback allows only "code kind":
  isolate->SetModifyCodeGenerationFromStringsCallback(
      [](v8::Local<v8::Context> context, v8::Local<v8::Value> source,
         bool is_code_like) -> v8::ModifyCodeGenerationFromStringsResult {
        bool ok = is_code_like ||
                  (source->IsObject() &&
                   source.As<v8::Object>()->IsCodeLike(context->GetIsolate()));
        return {ok, v8_str("(function anonymous(\n) {\nreturn 7;\n})\n")};
      });
  CHECK(CompileRun("new Function(new Other())()").IsEmpty());
  ExpectInt32("new Function(new CodeLike())()", 7);
}

THREADED_TEST(MicrotaskQueueOfContext) {
  auto microtask_queue = v8::MicrotaskQueue::New(CcTest::isolate());
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<Context> context = Context::New(
      CcTest::isolate(), nullptr, v8::MaybeLocal<ObjectTemplate>(),
      v8::MaybeLocal<Value>(), v8::DeserializeInternalFieldsCallback(),
      microtask_queue.get());
  CHECK_EQ(context->GetMicrotaskQueue(), microtask_queue.get());
}

THREADED_TEST(SetMicrotaskQueueOfContext) {
  auto microtask_queue = v8::MicrotaskQueue::New(CcTest::isolate());
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<Context> context = Context::New(
      CcTest::isolate(), nullptr, v8::MaybeLocal<ObjectTemplate>(),
      v8::MaybeLocal<Value>(), v8::DeserializeInternalFieldsCallback(),
      microtask_queue.get());
  CHECK_EQ(context->GetMicrotaskQueue(), microtask_queue.get());

  auto new_microtask_queue = v8::MicrotaskQueue::New(CcTest::isolate());
  context->SetMicrotaskQueue(new_microtask_queue.get());
  CHECK_EQ(context->GetMicrotaskQueue(), new_microtask_queue.get());
}

namespace {

bool MockSabConstructorEnabledCallback(v8::Local<v8::Context>) { return true; }

bool MockSabConstructorDisabledCallback(v8::Local<v8::Context>) {
  return false;
}

}  // namespace

TEST(TestSetSabConstructorEnabledCallback) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = v8::Context::New(CcTest::isolate());
  i::Handle<i::NativeContext> i_context = v8::Utils::OpenHandle(*context);

  // No callback
  i::v8_flags.enable_sharedarraybuffer_per_context = false;
  CHECK(i_isolate->IsSharedArrayBufferConstructorEnabled(i_context));

  i::v8_flags.enable_sharedarraybuffer_per_context = true;
  CHECK(!i_isolate->IsSharedArrayBufferConstructorEnabled(i_context));

  // Callback returns false
  isolate->SetSharedArrayBufferConstructorEnabledCallback(
      MockSabConstructorDisabledCallback);

  i::v8_flags.enable_sharedarraybuffer_per_context = false;
  CHECK(i_isolate->IsSharedArrayBufferConstructorEnabled(i_context));

  i::v8_flags.enable_sharedarraybuffer_per_context = true;
  CHECK(!i_isolate->IsSharedArrayBufferConstructorEnabled(i_context));

  // Callback returns true
  isolate->SetSharedArrayBufferConstructorEnabledCallback(
      MockSabConstructorEnabledCallback);

  i::v8_flags.enable_sharedarraybuffer_per_context = false;
  CHECK(i_isolate->IsSharedArrayBufferConstructorEnabled(i_context));

  i::v8_flags.enable_sharedarraybuffer_per_context = true;
  CHECK(i_isolate->IsSharedArrayBufferConstructorEnabled(i_context));
}

namespace {
void NodeTypeCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::Number::New(isolate, 1));
}
}  // namespace

TEST(EmbedderInstanceTypes) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  i::v8_flags.experimental_embedder_instance_types = true;
  Local<FunctionTemplate> node = FunctionTemplate::New(isolate);
  Local<ObjectTemplate> proto_template = node->PrototypeTemplate();

  enum JSApiInstanceType : uint16_t {
    kGenericApiObject = 0,  // FunctionTemplateInfo::kNoJSApiObjectType.
    kElement,
    kHTMLElement,
    kHTMLDivElement,
  };

  Local<FunctionTemplate> nodeType = v8::FunctionTemplate::New(
      isolate, NodeTypeCallback, Local<Value>(),
      v8::Signature::New(isolate, node), 0, v8::ConstructorBehavior::kThrow,
      v8::SideEffectType::kHasSideEffect, nullptr, kGenericApiObject, kElement,
      kHTMLDivElement);
  proto_template->SetAccessorProperty(
      String::NewFromUtf8Literal(isolate, "nodeType"), nodeType);

  Local<FunctionTemplate> element = FunctionTemplate::New(
      isolate, nullptr, Local<Value>(), Local<v8::Signature>(), 0,
      v8::ConstructorBehavior::kAllow, v8::SideEffectType::kHasSideEffect,
      nullptr, kElement);
  element->Inherit(node);

  Local<FunctionTemplate> html_element = FunctionTemplate::New(
      isolate, nullptr, Local<Value>(), Local<v8::Signature>(), 0,
      v8::ConstructorBehavior::kAllow, v8::SideEffectType::kHasSideEffect,
      nullptr, kHTMLElement);
  html_element->Inherit(element);

  Local<FunctionTemplate> div_element = FunctionTemplate::New(
      isolate, nullptr, Local<Value>(), Local<v8::Signature>(), 0,
      v8::ConstructorBehavior::kAllow, v8::SideEffectType::kHasSideEffect,
      nullptr, kHTMLDivElement);
  div_element->Inherit(html_element);

  CHECK(env->Global()
            ->Set(env.local(), v8_str("div"),
                  div_element->GetFunction(env.local())
                      .ToLocalChecked()
                      ->NewInstance(env.local())
                      .ToLocalChecked())
            .FromJust());

  CompileRun("var x = div.nodeType;");

  Local<Value> res =
      env->Global()->Get(env.local(), v8_str("x")).ToLocalChecked();
  CHECK_EQ(1, res->ToInt32(env.local()).ToLocalChecked()->Value());
}

template <typename T>
void TestCopyAndMoveConstructionAndAssignment() {
  // A struct with deprecated fields will trigger a deprecation warning when
  // using the copy or move constructor (without special care), see
  // https://crbug.com/v8/13092.

  T orig;
  // Use move constructor.
  T moved{std::move(orig)};
  // Use copy constructor.
  T copied{moved};

  // Use move assignment.
  orig = std::move(moved);
  // Use copy assignment.
  orig = copied;
}

UNINITIALIZED_TEST(IsolateCreateParamsIsMovableAndCopyable) {
  // Test that we can use the move- and copy constructor of
  // Isolate::CreateParams.
  TestCopyAndMoveConstructionAndAssignment<v8::Isolate::CreateParams>();
}

UNINITIALIZED_TEST(OOMDetailsAreMovableAndCopyable) {
  TestCopyAndMoveConstructionAndAssignment<v8::OOMDetails>();
}

UNINITIALIZED_TEST(JitCodeEventIsMovableAndCopyable) {
  TestCopyAndMoveConstructionAndAssignment<v8::JitCodeEvent>();
}

#if V8_ENABLE_WEBASSEMBLY
TEST(WasmAbortStreamingAfterContextDisposal) {
  // This is a regression test for https://crbug.com/1403531.

  class Resolver final : public i::wasm::CompilationResultResolver {
   public:
    void OnCompilationSucceeded(
        i::Handle<i::WasmModuleObject> result) override {
      UNREACHABLE();
    }
    void OnCompilationFailed(i::Handle<i::Object> error_reason) override {
      UNREACHABLE();
    }
  };

  auto resolver = std::make_shared<Resolver>();

  std::unique_ptr<v8::WasmStreaming> wasm_streaming;
  v8::Isolate* isolate = CcTest::isolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  {
    v8::HandleScope scope(isolate);
    LocalContext context;

    wasm_streaming =
        i::wasm::StartStreamingForTesting(i_isolate, std::move(resolver));
    isolate->ContextDisposedNotification(false);
  }

  wasm_streaming->Abort({});
  wasm_streaming.reset();
}
#endif  // V8_ENABLE_WEBASSEMBLY

TEST(DeepFreezeIncompatibleTypes) {
  const int numCases = 7;
  struct {
    const char* script;
    const char* exception;
  } test_cases[numCases] = {
      {
          R"(
        "use strict"
        let foo = 1;
      )",
          "TypeError: Cannot DeepFreeze non-const value foo"},
      {
          R"(
        "use strict"
        const foo = 1;
        const generator = function*() {
          yield 1;
          yield 2;
        }
        const gen = generator();
      )",
          "TypeError: Cannot DeepFreeze object of type Generator"},
      {
          R"(
        "use strict"
        const incrementer = (function() {
          let a = 1;
          return function() { a += 1; return a; };
        })();
      )",
          "TypeError: Cannot DeepFreeze non-const value a"},
      {
          R"(
      let a = new Number();
      )",
          "TypeError: Cannot DeepFreeze non-const value a"},
      {
          R"(
      const a = [0, 1, 2, 3, 4, 5];
      var it = a[Symbol.iterator]();
      function foo() {
         return it.next().value;
          }
      foo();
      )",
          "TypeError: Cannot DeepFreeze object of type Array Iterator"},
      {
          R"(
      const a = "0123456789";
      var it = a[Symbol.iterator]();
      function foo() {
         return it.next().value;
          }
      foo();
      )",
          "TypeError: Cannot DeepFreeze object of type Object"},
      {R"(
      const a = "0123456789";
      var it = a.matchAll(/\d/g);
      function foo() {
         return it.next().value;
          }
      foo();
      )",
       "TypeError: Cannot DeepFreeze object of type Object"},
  };

  for (int idx = 0; idx < numCases; idx++) {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = env.local();
    v8::Maybe<void> maybe_success = v8::Nothing<void>();
    CompileRun(context, test_cases[idx].script);
    v8::TryCatch tc(isolate);
    maybe_success = context->DeepFreeze(nullptr);
    CHECK(maybe_success.IsNothing());
    CHECK(tc.HasCaught());
    v8::String::Utf8Value uS(isolate, tc.Exception());
    std::string exception(*uS, uS.length());
    CHECK_EQ(std::string(test_cases[idx].exception), exception);
  }
}

TEST(DeepFreezeIsFrozen) {
  const int numCases = 10;
  struct {
    const char* script;
    const char* exception;
    int32_t expected;
  } test_cases[numCases] = {
      {// Closure
       R"(
        const incrementer = (function() {
          const a = {b: 1};
          return function() { a.b += 1; return a.b; };
        })();
        const foo = function() { return incrementer(); }
        foo();
      )",
       nullptr, 2},
      {
          R"(
        const incrementer = (function() {
          const a = {b: 1};
          return function() { a.b += 1; return a.b; };
        })();
        const foo = function() { return incrementer(); }
        foo();
      )",
          nullptr, 2},
      {// Array
       R"(
        const a = [0, -1, -2];
        const foo = function() { a[0] += 1; return a[0]; }
      )",
       nullptr, 0},
      {
          R"(
        const a = [0, -1, -2];
        const foo = function() { a[0] += 1; return a[0]; }
      )",
          nullptr, 0},
      {// Wrapper Objects
       R"(
        const a = {b: new Number()};
        const foo = function() {
          a.b = new Number(a.b + 1);
          return a.b.valueOf();
        }
      )",
       nullptr, 0},
      {// Functions
       // Assignment to constant doesn't work.
       R"(
        const foo = function() {
          foo = function() { return 2;}
          return 1;
        }
      )",
       "TypeError: Assignment to constant variable.", 0},
      {
          R"(
        const a = {b: {c: {d: {e: {f: 1}}}}};
        const foo = function() {
          a.b.c.d.e.f += 1;
          return a.b.c.d.e.f;
        }
      )",
          nullptr, 1},
      {
          R"(
        const foo = function() {
          if (!('count' in globalThis))
            globalThis.count = 1;
          ++count;
          return count;
        }
      )",
          "ReferenceError: count is not defined", 0},
      {
          R"(
        const countPrototype = {
          get() {
            return 1;
          },
        };
        const count = Object.create(countPrototype);
        function foo() {
          const curr_count = count.get();
          count.prototype = { get() { return curr_count + 1; }};
          return count.get();
        }
      )",
          nullptr, 1},
      {
          R"(
          const a = (function(){
            function A(){};
            A.o = 1;
            return new A();
          })();
        function foo() {
          a.constructor.o++;
          return a.constructor.o;
        }
      )",
          nullptr, 1},
  };
  for (int idx = 0; idx < numCases; idx++) {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = env.local();
    v8::Maybe<void> maybe_success = v8::Nothing<void>();
    v8::TryCatch tc(isolate);
    v8::MaybeLocal<v8::Value> status =
        CompileRun(context, test_cases[idx].script);
    CHECK(!status.IsEmpty());
    CHECK(!tc.HasCaught());

    maybe_success = context->DeepFreeze(nullptr);
    CHECK(!tc.HasCaught());
    status = CompileRun(context, "foo()");

    if (test_cases[idx].exception) {
      CHECK(tc.HasCaught());
      v8::String::Utf8Value uS(isolate, tc.Exception());
      std::string exception(*uS, uS.length());
      CHECK_EQ(std::string(test_cases[idx].exception), exception);
    } else {
      CHECK(!tc.HasCaught());
      CHECK(!status.IsEmpty());
      ExpectInt32("foo()", test_cases[idx].expected);
    }
  }
}

TEST(DeepFreezeAllowsSyntax) {
  const int numCases = 2;
  struct {
    const char* script;
    int32_t expected;
  } test_cases[numCases] = {
      {
          R"(
      const a = 1;
      function foo() {
        let b = 4;
        b += 1;
        return a + b;
      }
    )",
          6,
      },
      {
          R"(
      var a = 1;
      function foo() {
        let b = 4;
        b += 1;
        return a + b;
      }
    )",
          6,
      }};  // TODO(behamilton): Add more cases that should be supported.
  for (int idx = 0; idx < numCases; idx++) {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = env.local();
    v8::Maybe<void> maybe_success = v8::Nothing<void>();
    v8::MaybeLocal<v8::Value> status =
        CompileRun(context, test_cases[idx].script);
    CHECK(!status.IsEmpty());
    maybe_success = context->DeepFreeze(nullptr);
    CHECK(!maybe_success.IsNothing());
    ExpectInt32("foo()", test_cases[idx].expected);
  }
}

namespace {

class AllowEmbedderObjects : public v8::Context::DeepFreezeDelegate {
 public:
  bool FreezeEmbedderObjectAndGetChildren(
      v8::Local<v8::Object> obj,
      v8::LocalVector<v8::Object>& children_out) override {
    return true;
  }
};

}  // namespace

TEST(DeepFreezesJSApiObjectWithDelegate) {
  const int numCases = 3;
  struct {
    const char* script;
    std::function<void()> run_check;
  } test_cases[numCases] = {
      {
          R"(
          globalThis.jsApiObject.foo = {test: 4};
          function foo() {
            globalThis.jsApiObject.foo.test++;
            return globalThis.jsApiObject.foo.test;
          }
          foo();
        )",
          []() { ExpectInt32("foo()", 5); }},
      {
          R"(
          function foo() {
            if (!('foo' in globalThis.jsApiObject))
              globalThis.jsApiObject.foo = {test: 4}
            globalThis.jsApiObject.foo.test++;
            return globalThis.jsApiObject.foo.test;
          }
          foo();
        )",
          []() { ExpectInt32("foo()", 5); }},
      {
          R"(
          function foo() {
            if (!('foo' in globalThis.jsApiObject))
              globalThis.jsApiObject.foo = 4
            globalThis.jsApiObject.foo++;
            return globalThis.jsApiObject.foo;
          }
        )",
          []() { ExpectUndefined("foo()"); }},
  };

  for (int idx = 0; idx < numCases; idx++) {
    v8::Isolate* isolate = CcTest::isolate();
    v8::HandleScope scope(isolate);
    v8::Local<v8::ObjectTemplate> global_template =
        v8::ObjectTemplate::New(isolate);
    v8::Local<v8::FunctionTemplate> v8_template =
        v8::FunctionTemplate::New(isolate, &DoNothingCallback);
    v8_template->RemovePrototype();
    global_template->Set(v8_str("jsApiObject"), v8_template);

    LocalContext env(isolate, /*extensions=*/nullptr, global_template);
    v8::Local<v8::Context> context = env.local();

    v8::TryCatch tc(isolate);
    v8::MaybeLocal<v8::Value> status =
        CompileRun(context, test_cases[idx].script);
    CHECK(!tc.HasCaught());
    CHECK(!status.IsEmpty());

    AllowEmbedderObjects delegate;
    v8::Maybe<void> maybe_success = context->DeepFreeze(&delegate);
    CHECK(!tc.HasCaught());
    CHECK(!maybe_success.IsNothing());

    test_cases[idx].run_check();
  }
}

namespace {

class MyObject {
 public:
  bool Freeze() {
    was_frozen_ = true;
    return true;
  }

  bool was_frozen_ = false;
  v8::Local<v8::Object> internal_data_;
};

class HiddenDataDelegate : public v8::Context::DeepFreezeDelegate {
 public:
  explicit HiddenDataDelegate(v8::Local<v8::External> my_object)
      : my_object_(my_object) {}

  bool FreezeEmbedderObjectAndGetChildren(
      v8::Local<v8::Object> obj,
      v8::LocalVector<v8::Object>& children_out) override {
    int fields = obj->InternalFieldCount();
    for (int idx = 0; idx < fields; idx++) {
      v8::Local<v8::Value> child_value =
          obj->GetInternalField(idx).As<v8::Value>();
      if (child_value->IsExternal()) {
        if (!FreezeExternal(v8::Local<v8::External>::Cast(child_value),
                            children_out)) {
          return false;
        }
      }
    }
    if (obj->IsExternal()) {
      return FreezeExternal(v8::Local<v8::External>::Cast(obj), children_out);
    }
    return true;
  }

 private:
  bool FreezeExternal(v8::Local<v8::External> ext,
                      v8::LocalVector<v8::Object>& children_out) {
    if (ext->Value() == my_object_->Value()) {
      MyObject* my_obj = static_cast<MyObject*>(ext->Value());
      if (my_obj->Freeze()) {
        children_out.push_back(my_obj->internal_data_);
        return true;
      }
    }
    return false;
  }

  v8::Local<v8::External> my_object_;
};

}  // namespace

TEST(DeepFreezeDoesntFreezeJSApiObjectFunctionData) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  MyObject foo;
  v8::Local<v8::External> v8_foo = v8::External::New(isolate, &foo);

  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  v8::Local<v8::FunctionTemplate> v8_template =
      v8::FunctionTemplate::New(isolate, &DoNothingCallback, /*data=*/v8_foo);
  v8_template->RemovePrototype();
  global_template->Set(v8_str("jsApiObject"), v8_template);

  LocalContext env(isolate, /*extensions=*/nullptr, global_template);
  v8::Local<v8::Context> context = env.local();

  foo = {false, v8::Object::New(isolate)};

  HiddenDataDelegate hdd{v8_foo};
  v8::TryCatch tc(isolate);

  v8::Maybe<void> maybe_success = context->DeepFreeze(&hdd);

  CHECK(!maybe_success.IsNothing());
  CHECK(!foo.was_frozen_);

  v8::Local<v8::String> param_list[] = {v8_str("obj")};
  v8::Local<v8::Value> params[] = {
      v8::Local<v8::Value>::Cast(foo.internal_data_)};
  v8::ScriptCompiler::Source source{v8_str("return Object.isFrozen(obj)")};
  v8::Local<v8::Function> is_frozen =
      v8::ScriptCompiler::CompileFunction(context, &source, 1, param_list)
          .ToLocalChecked();
  v8::MaybeLocal<v8::Value> result =
      is_frozen->Call(context, context->Global(), 1, params);

  CHECK(!result.IsEmpty());
  CHECK(result.ToLocalChecked()->IsFalse());
}

TEST(DeepFreezeForbidsJSApiObjectWithoutDelegate) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  v8::Local<v8::ObjectTemplate> v8_template = v8::ObjectTemplate::New(isolate);
  v8_template->SetInternalFieldCount(1);
  global_template->Set(v8_str("jsApiObject"), v8_template);

  LocalContext env(isolate, /*extensions=*/nullptr, global_template);
  v8::Local<v8::Context> context = env.local();

  MyObject foo{false, v8::Object::New(isolate)};
  v8::Local<v8::External> v8_foo = v8::External::New(isolate, &foo);

  v8::Local<v8::Value> val =
      context->Global()->Get(context, v8_str("jsApiObject")).ToLocalChecked();
  CHECK(val->IsObject());
  v8::Local<v8::Object> obj = v8::Local<v8::Object>::Cast(val);
  CHECK_EQ(1, obj->InternalFieldCount());
  obj->SetInternalField(0, v8_foo);

  v8::TryCatch tc(isolate);
  v8::Maybe<void> maybe_success = context->DeepFreeze(nullptr);

  CHECK(tc.HasCaught());
  v8::String::Utf8Value uS(isolate, tc.Exception());
  std::string exception(*uS, uS.length());
  CHECK_EQ(std::string("TypeError: Cannot DeepFreeze object of type Object"),
           exception);
  CHECK(maybe_success.IsNothing());
}

TEST(DeepFreezeFreezesJSApiObjectData) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  v8::Local<v8::ObjectTemplate> v8_template = v8::ObjectTemplate::New(isolate);
  v8_template->SetInternalFieldCount(1);
  global_template->Set(v8_str("jsApiObject"), v8_template);

  LocalContext env(isolate, /*extensions=*/nullptr, global_template);
  v8::Local<v8::Context> context = env.local();

  MyObject foo{false, v8::Object::New(isolate)};
  v8::Local<v8::External> v8_foo = v8::External::New(isolate, &foo);

  v8::Local<v8::Value> val =
      context->Global()->Get(context, v8_str("jsApiObject")).ToLocalChecked();
  CHECK(val->IsObject());
  v8::Local<v8::Object> obj = v8::Local<v8::Object>::Cast(val);
  CHECK_EQ(1, obj->InternalFieldCount());
  obj->SetInternalField(0, v8_foo);

  HiddenDataDelegate hdd{v8_foo};

  v8::TryCatch tc(isolate);

  v8::Maybe<void> maybe_success = context->DeepFreeze(&hdd);

  CHECK(!maybe_success.IsNothing());
  CHECK(foo.was_frozen_);

  v8::Local<v8::String> param_list[] = {v8_str("obj")};
  v8::Local<v8::Value> params[] = {
      v8::Local<v8::Value>::Cast(foo.internal_data_)};
  v8::ScriptCompiler::Source source{v8_str("return Object.isFrozen(obj)")};
  v8::Local<v8::Function> is_frozen =
      v8::ScriptCompiler::CompileFunction(context, &source, 1, param_list)
          .ToLocalChecked();
  v8::MaybeLocal<v8::Value> result =
      is_frozen->Call(context, context->Global(), 1, params);

  CHECK(!result.IsEmpty());
  CHECK(result.ToLocalChecked()->IsTrue());
}

TEST(DeepFreezeFreezesExternalObjectData) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = env.local();

  MyObject foo{false, v8::Object::New(isolate)};
  v8::Local<v8::External> v8_foo = v8::External::New(isolate, &foo);
  v8::Maybe<bool> success =
      context->Global()->CreateDataProperty(context, v8_str("foo"), v8_foo);
  CHECK(!success.IsNothing() && success.FromJust());

  HiddenDataDelegate hdd{v8_foo};

  v8::Maybe<void> maybe_success = context->DeepFreeze(&hdd);

  CHECK(!maybe_success.IsNothing());
  CHECK(foo.was_frozen_);

  v8::Local<v8::String> param_list[] = {v8_str("obj")};
  v8::Local<v8::Value> params[] = {
      v8::Local<v8::Value>::Cast(foo.internal_data_)};
  v8::ScriptCompiler::Source source{v8_str("return Object.isFrozen(obj)")};
  v8::Local<v8::Function> is_frozen =
      v8::ScriptCompiler::CompileFunction(context, &source, 1, param_list)
          .ToLocalChecked();
  v8::MaybeLocal<v8::Value> result =
      is_frozen->Call(context, context->Global(), 1, params);

  CHECK(!result.IsEmpty());
  CHECK(result.ToLocalChecked()->IsTrue());
}

namespace {
void handle_property(Local<Name> name,
                     const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(900));
}

void handle_property_2(Local<Name> name,
                       const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(902));
}

void handle_property(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK_EQ(0, info.Length());
  info.GetReturnValue().Set(v8_num(907));
}

}  // namespace

TEST(DeepFreezeInstantiatesAccessors) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
  Local<v8::FunctionTemplate> getter_templ =
      v8::FunctionTemplate::New(isolate, handle_property);
  getter_templ->SetLength(0);
  fun_templ->SetAccessorProperty(v8_str("bar"), getter_templ);
  fun_templ->SetNativeDataProperty(v8_str("instance_foo"), handle_property);
  fun_templ->SetNativeDataProperty(v8_str("object_foo"), handle_property_2);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("Fun"), fun).FromJust());

  v8::Local<v8::Context> context = env.local();
  v8::Maybe<void> maybe_success = context->DeepFreeze(nullptr);
  CHECK(!maybe_success.IsNothing());
}

namespace {
void handle_object_property(v8::Local<v8::Name> property,
                            const v8::PropertyCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_num(909));
}
}  // namespace

TEST(DeepFreezeInstantiatesAccessors2) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::ObjectTemplate> fun_templ = v8::ObjectTemplate::New(isolate);
  fun_templ->SetNativeDataProperty(v8_str("foo"), handle_object_property);
  Local<v8::FunctionTemplate> getter_templ =
      v8::FunctionTemplate::New(isolate, handle_property);
  getter_templ->SetLength(0);
  fun_templ->SetAccessorProperty(v8_str("bar"), getter_templ);
  fun_templ->SetNativeDataProperty(v8_str("instance_foo"), handle_property);
  fun_templ->SetNativeDataProperty(v8_str("object_foo"), handle_property_2);
  Local<Object> fun = fun_templ->NewInstance(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("Fun"), fun).FromJust());

  v8::Local<v8::Context> context = env.local();
  v8::Maybe<void> maybe_success = context->DeepFreeze(nullptr);
  CHECK(!maybe_success.IsNothing());
}

void GetIsolatePreservedContinuationData(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(
      info.GetIsolate()->GetContinuationPreservedEmbedderData());
}

TEST(ContinuationPreservedEmbedderData) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();

  isolate->SetContinuationPreservedEmbedderData(v8_str("foo"));

  v8::Local<v8::Function> get_isolate_preserved_data =
      v8::Function::New(context.local(), GetIsolatePreservedContinuationData,
                        v8_str("get_isolate_preserved_data"))
          .ToLocalChecked();
  Local<v8::Promise> p1 =
      resolver->GetPromise()
          ->Then(context.local(), get_isolate_preserved_data)
          .ToLocalChecked();

  isolate->SetContinuationPreservedEmbedderData(v8::Undefined(isolate));

  resolver->Resolve(context.local(), v8::Undefined(isolate)).FromJust();
  isolate->PerformMicrotaskCheckpoint();

#if V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  CHECK(v8_str("foo")->SameValue(p1->Result()));
#else
  CHECK(p1->Result()->IsUndefined());
#endif
}

TEST(ContinuationPreservedEmbedderDataCle
"""


```