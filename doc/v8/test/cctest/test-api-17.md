Response: The user wants a summary of the C++ code provided in the file `v8/test/cctest/test-api.cc`. They specifically want to know the functionality of the code and if it relates to JavaScript. If it does, they want an illustrative example in JavaScript.

The code seems to be a series of C++ tests for the V8 JavaScript engine's C++ API. It focuses on various aspects of the API, including:

1. **`IsCodeLike`**:  Testing the behavior of objects marked as "code-like" when used with `eval` and `new Function`.
2. **`ModifyCodeGenerationFromStringsCallback`**: Testing how the callback that modifies code generation from strings affects `eval` and `new Function`, especially in conjunction with "code-like" objects.
3. **Microtask Queues**: Testing the creation and manipulation of microtask queues associated with V8 contexts.
4. **`SetSabConstructorEnabledCallback`**: Testing a callback that controls whether the `SharedArrayBuffer` constructor is enabled in a given context.
5. **Embedder Instance Types**: Testing the experimental feature for associating custom instance types with JavaScript objects created from templates.
6. **Move and Copy Semantics**: Testing that certain V8 API classes (`Isolate::CreateParams`, `OOMDetails`, `JitCodeEvent`) support move and copy construction/assignment.
7. **Wasm Streaming Abortion**: Testing the behavior of WebAssembly streaming compilation when the context is disposed of.
8. **`DeepFreeze`**:  Extensive testing of the `Context::DeepFreeze` API, including:
    - Errors when trying to deep-freeze non-constant values or certain object types (like generators, closures with mutable state, iterators, `matchAll` results).
    - Cases where deep-freezing is successful and prevents further modifications.
    - Testing scenarios involving syntax and code execution after deep-freezing.
    - Testing `DeepFreeze` with a delegate to handle freezing of embedder objects and their internal data.
    - Testing how `DeepFreeze` interacts with JSApi objects, functions with data, and external objects.
    - Testing if `DeepFreeze` instantiates accessors.
9. **Continuation Preserved Embedder Data**: Testing the mechanism for preserving embedder data across promise continuations and microtasks.
10. **Wrapped Functions and Classes**: Testing a scenario where a wrapped function contains a class definition starting at the first character.

Let's break down the major functional areas and provide JavaScript examples where applicable.
This C++ code file, `test-api.cc`, is part of the V8 JavaScript engine's test suite. Specifically, this section focuses on testing various aspects of the V8 C++ API related to:

**Core Functionality and its Relation to JavaScript:**

1. **`IsCodeLike` Objects and Code Execution (JavaScript: `eval`, `new Function`)**:
    *   This section tests a feature where objects can be marked as "code-like". When such an object is used in contexts like `eval()` or `new Function()`, its string representation is always treated as code to be executed, regardless of whether the context allows code generation from strings.
    *   **JavaScript Example:**
        ```javascript
        // Assuming the C++ code has set up 'CodeLike' and 'Other' object types
        const codeLikeInstance = new CodeLike();
        const otherInstance = new Other();

        console.log(eval(codeLikeInstance)); // Always executes the string representation (e.g., "2+2")
        console.log(eval(otherInstance));   // Behaves like a normal object, might return the object itself or its string representation

        const codeLikeFunction = new Function(codeLikeInstance); // Always treats the string as code
        const otherFunction = new Function(otherInstance);     // Might treat it differently depending on context
        ```

2. **`ModifyCodeGenerationFromStringsCallback` (JavaScript: `eval`, `new Function`)**:
    *   This tests a mechanism to intercept and potentially modify or disallow the compilation of code from strings (used by `eval` and `new Function`). The tests verify how this callback interacts with both regular objects and "code-like" objects.
    *   **JavaScript Example (Conceptual):**
        ```javascript
        // In C++, a callback is registered to modify strings before evaluation.
        // This callback could, for instance, replace "2+2" with "3+3".

        const myObject = { toString: () => "2+2" };
        console.log(eval(myObject)); // Might output 4 if no modification, or 6 if the callback modified it.

        const myFunction = new Function(myObject); // Similar modification could occur here.
        ```

3. **Microtask Queues (JavaScript: `Promise.resolve().then()`, `queueMicrotask`)**:
    *   This part tests the creation and association of microtask queues with V8 contexts. Microtasks are a way to schedule tasks that execute after the current JavaScript task but before the event loop continues.
    *   **JavaScript Example:**
        ```javascript
        Promise.resolve().then(() => {
          console.log("This is a microtask.");
        });

        queueMicrotask(() => {
          console.log("This is another microtask.");
        });

        console.log("This is a regular task.");
        // Output order will be:
        // "This is a regular task."
        // "This is a microtask."
        // "This is another microtask."
        ```

4. **`SetSabConstructorEnabledCallback` (JavaScript: `SharedArrayBuffer`)**:
    *   This tests a callback that allows embedders to control whether the `SharedArrayBuffer` constructor is available in a specific context. `SharedArrayBuffer` is used for sharing memory between different JavaScript contexts or workers.
    *   **JavaScript Example (Conditional):**
        ```javascript
        // Depending on the C++ callback's configuration, the following might work or throw an error
        const sab = new SharedArrayBuffer(1024);
        ```

5. **Embedder Instance Types (JavaScript:  Object Creation and Access)**:
    *   This tests an experimental feature where custom instance types can be associated with objects created from templates. This allows embedders to have more fine-grained control over object behavior and identification.
    *   **JavaScript Example (Conceptual):**
        ```javascript
        // Assuming C++ code has defined types like 'Element', 'HTMLElement', 'HTMLDivElement'
        const div = new div(); // 'div' is an object created based on the 'HTMLDivElement' template
        console.log(div.nodeType); // The C++ code sets up a getter for 'nodeType'
        ```

6. **Move and Copy Semantics (C++ Internal)**:
    *   This section focuses on testing the C++ implementation details of certain V8 API classes. It ensures that these classes can be correctly copied and moved in C++, which is important for performance and memory management. This doesn't directly translate to observable JavaScript behavior but affects the underlying engine's efficiency.

7. **Wasm Streaming Abortion (JavaScript: WebAssembly Streaming Compilation)**:
    *   This tests how V8 handles aborting WebAssembly streaming compilation if the JavaScript context is disposed of during the process. This is relevant for scenarios where WebAssembly modules are loaded asynchronously.
    *   **JavaScript Example:**
        ```javascript
        // Example of initiating streaming compilation (simplified)
        WebAssembly.instantiateStreaming(fetch('module.wasm'))
          .then(result => {
            // Module is ready
          })
          .catch(error => {
            // Compilation failed or was aborted
          });
        // If the context is destroyed while 'fetch' is in progress, this test checks how V8 handles it.
        ```

8. **`DeepFreeze` API (JavaScript: `Object.deepFreeze`)**:
    *   This tests the `Context::DeepFreeze` API, which aims to recursively freeze an object and its properties, making them immutable. It checks various edge cases, including trying to freeze non-constant values, certain built-in types, and verifies that frozen objects cannot be modified.
    *   **JavaScript Example:**
        ```javascript
        const obj = { a: 1, b: { c: 2 } };
        Object.deepFreeze(obj);

        obj.a = 3; // TypeError: Cannot assign to read only property 'a' of object '#<Object>'
        obj.b.c = 4; // TypeError: Cannot assign to read only property 'c' of object '#<Object>'
        ```

9. **Continuation Preserved Embedder Data (JavaScript: `Promise.then()`, Microtasks)**:
    *   This tests a feature to preserve embedder-specific data across asynchronous operations like promise continuations and microtasks. This allows embedders to maintain state and context across these boundaries.
    *   **JavaScript Example (Conceptual):**
        ```javascript
        // C++ code sets some "embedder data"
        Promise.resolve().then(() => {
          // The C++ code can access the "embedder data" here, even after the promise resolves.
        });
        ```

10. **Wrapped Functions with Classes (JavaScript: Class Declarations)**:
    *   This tests a specific scenario involving compiling a wrapped function that contains a class declaration starting at the beginning of the code. It ensures that the V8 parser correctly handles this case, even after bytecode flushing.
    *   **JavaScript Example:**
        ```javascript
        const MyClassWrapper = new Function('return class MyClass {}')();
        const instance = new MyClassWrapper();
        ```

In summary, this code file thoroughly tests different functionalities of the V8 C++ API, many of which directly relate to how JavaScript code is executed and managed within the V8 engine. The tests cover areas like code evaluation, asynchronous operations, object immutability, and how embedders can interact with and extend the JavaScript environment.

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第18部分，共18部分，请归纳一下它的功能

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

TEST(ContinuationPreservedEmbedderDataClearedAndRestored) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  v8::Local<v8::Function> get_isolate_preserved_data =
      v8::Function::New(context.local(), GetIsolatePreservedContinuationData,
                        v8_str("get_isolate_preserved_data"))
          .ToLocalChecked();
  Local<v8::Promise> p1 =
      resolver->GetPromise()
          ->Then(context.local(), get_isolate_preserved_data)
          .ToLocalChecked();
  isolate->SetContinuationPreservedEmbedderData(v8_str("foo"));
  resolver->Resolve(context.local(), v8::Undefined(isolate)).FromJust();
  isolate->PerformMicrotaskCheckpoint();
  CHECK(p1->Result()->IsUndefined());
#if V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  CHECK(v8_str("foo")->SameValue(
      isolate->GetContinuationPreservedEmbedderData()));
#else
  CHECK(isolate->GetContinuationPreservedEmbedderData()->IsUndefined());
#endif
}

static bool did_callback_microtask_run = false;
static void CallbackTaskMicrotask(void* data) {
  did_callback_microtask_run = true;
  v8::Isolate* isolate = static_cast<v8::Isolate*>(data);
#if V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  CHECK(v8_str("foo")->SameValue(
      isolate->GetContinuationPreservedEmbedderData()));
#else
  CHECK(isolate->GetContinuationPreservedEmbedderData()->IsUndefined());
#endif
}

TEST(EnqueMicrotaskContinuationPreservedEmbedderData_CallbackTask) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetContinuationPreservedEmbedderData(v8_str("foo"));
  isolate->EnqueueMicrotask(&CallbackTaskMicrotask, isolate);
  isolate->SetContinuationPreservedEmbedderData(v8::Undefined(isolate));

  isolate->PerformMicrotaskCheckpoint();
  CHECK(did_callback_microtask_run);
}

static bool did_callable_microtask_run = false;
static void CallableTaskMicrotask(const v8::FunctionCallbackInfo<Value>& info) {
  did_callable_microtask_run = true;
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  CHECK(v8_str("foo")->SameValue(
      info.GetIsolate()->GetContinuationPreservedEmbedderData()));
#else
  CHECK(
      info.GetIsolate()->GetContinuationPreservedEmbedderData()->IsUndefined());
#endif
}

TEST(EnqueMicrotaskContinuationPreservedEmbedderData_CallableTask) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetContinuationPreservedEmbedderData(v8_str("foo"));
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), CallableTaskMicrotask).ToLocalChecked());
  isolate->SetContinuationPreservedEmbedderData(v8::Undefined(isolate));

  isolate->PerformMicrotaskCheckpoint();
  CHECK(did_callable_microtask_run);
}

static bool did_thenable_callback_run = false;
static void ThenableCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  did_thenable_callback_run = true;
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  CHECK(v8_str("foo")->SameValue(
      info.GetIsolate()->GetContinuationPreservedEmbedderData()));
#else
  CHECK(
      info.GetIsolate()->GetContinuationPreservedEmbedderData()->IsUndefined());
#endif
  info.GetReturnValue().Set(true);
}

TEST(ContinuationPreservedEmbedderData_Thenable) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  CHECK(env->Global()
            ->Set(env.local(), v8_str("testContinuationData"),
                  v8::FunctionTemplate::New(isolate, ThenableCallback)
                      ->GetFunction(env.local())
                      .ToLocalChecked())
            .FromJust());

  v8::Local<Value> result = CompileRun(
      "var obj = { then: () => Promise.resolve().then(testContinuationData) }; "
      "obj");

  Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(env.local()).ToLocalChecked();

  isolate->SetContinuationPreservedEmbedderData(v8_str("foo"));
  resolver->Resolve(env.local(), result).FromJust();
  isolate->SetContinuationPreservedEmbedderData(v8::Undefined(isolate));

  isolate->PerformMicrotaskCheckpoint();
  CHECK(did_thenable_callback_run);
}

TEST(WrappedFunctionWithClass) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = env.local();

  // Compile a wrapped function whose first character is the start of a class.
  // This will mean that both the wrapped function and class's start position
  // will be character 0 -- things should still work.
  v8::ScriptCompiler::Source source{v8_str("class C{}; return C;")};
  v8::Local<v8::Function> wrapped_function =
      v8::ScriptCompiler::CompileFunction(context, &source, 0, nullptr)
          .ToLocalChecked();
  v8::Local<v8::Value> result =
      wrapped_function->Call(context, context->Global(), 0, nullptr)
          .ToLocalChecked();

  CHECK(result->IsFunction());
  v8::Local<v8::Function> the_class = v8::Local<v8::Function>::Cast(result);
  CHECK(the_class->IsConstructor());

  v8::MaybeLocal<v8::Object> maybe_instance =
      the_class->NewInstance(context, 0, nullptr);
  CHECK(!maybe_instance.IsEmpty());

  // Make sure the class still works after bytecode flushing.
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Handle<i::JSFunction> i_class =
      Cast<i::JSFunction>(v8::Utils::OpenHandle(*the_class));
  CHECK(i_class->shared()->CanDiscardCompiled());
  i::SharedFunctionInfo::DiscardCompiled(i_isolate,
                                         handle(i_class->shared(), i_isolate));
  i_class->ResetIfCodeFlushed(i_isolate);

  maybe_instance = the_class->NewInstance(context, 0, nullptr);
  CHECK(!maybe_instance.IsEmpty());
}

"""


```