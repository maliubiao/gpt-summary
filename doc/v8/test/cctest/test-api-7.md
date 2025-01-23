Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part 8 of a 18-part series of tests for the V8 JavaScript engine's C++ API. I should also explain how the code relates to JavaScript using examples.

Here's a breakdown of the code's functionality:

1. **Interceptors and Error Handling:**  The `InterceptorShouldThrowOnError` test examines how interceptors (which allow custom logic for property access) interact with JavaScript's strict mode and error handling (`ShouldThrowOnError`). It verifies that in strict mode, operations like setting or deleting properties via an interceptor can trigger errors that are catchable in JavaScript.

2. **Function Call Handlers and Side Effects:** Several tests (`CallHandlerHasNoSideEffect`, `FunctionTemplateNewHasNoSideEffect`, `FunctionTemplateNewWithCacheHasNoSideEffect`, `FunctionNewHasNoSideEffect`, `FunctionNewInstanceHasNoSideEffect`, `CallHandlerAsFunctionHasNoSideEffectNotSupported`) focus on the concept of side effects in function calls. V8 allows marking functions as having no side effects, which can be important for optimizations and security. These tests check how different ways of creating functions (using templates, with or without caches) and calling them (as regular functions or constructors) interact with this side-effect flag. They utilize `v8::debug::EvaluateGlobal` with `kDisableBreaksAndThrowOnSideEffect` to assert whether an operation is considered side-effect-free.

3. **`IsConstructCall` and `NewTarget`:**  The `IsConstructCall` and `NewTargetHandler` tests explore properties available within JavaScript function callbacks. `IsConstructCall` checks if a function was invoked as a constructor (`new`). `NewTarget` retrieves the `new.target` value within a function, which indicates the constructor that was originally called in a constructor invocation, including subclassing scenarios.

4. **`ObjectProtoToString` and `@@toStringTag`:** The `ObjectProtoToString` and `ObjectProtoToStringES6` tests investigate the behavior of the `Object.prototype.toString` method and the `Symbol.toStringTag` symbol. They verify that `ObjectProtoToString` (a C++ API function) provides the default `[object Object]` string representation, while the standard JavaScript `toString()` can be overridden, and `@@toStringTag` provides a mechanism to customize the string representation of objects in ES6 and later.

5. **`ObjectGetConstructorName`:** The `ObjectGetConstructorName` test examines how V8's C++ API can retrieve the constructor name of JavaScript objects, even in inheritance scenarios and with nested function expressions.

6. **Shared Objects and Constructor Names:** The `SharedObjectGetConstructorName` test checks if the `GetConstructorName` method works correctly for shared objects, which are a feature for sharing data between isolates (V8 execution environments). This test is conditional on certain V8 flags and multi-cage configurations.

7. **Threaded Tests and Fuzzing:**  A significant portion of the code introduces a framework for running tests concurrently using threads (`THREADED_TEST`). It includes a basic fuzzing mechanism (`ApiTestFuzzer`) to introduce randomness and potential race conditions into the tests, helping to uncover concurrency-related issues in the V8 API. The `Fuzz()` method simulates context switching between threads.

8. **Locking and Concurrency:** Several tests (`NestedLockers`, `NestedLockersNoTryCatch`, `RecursiveLocking`, `LockUnlockLock`) explore V8's locking mechanisms (`v8::Locker`, `v8::Unlocker`). They verify that nested locking works correctly and that it's possible to temporarily unlock and re-lock the V8 isolate.

9. **Global Object Management:** The `DontLeakGlobalObjects` test checks for memory leaks related to global objects. It creates and disposes of contexts and uses garbage collection to ensure that global objects are correctly cleaned up.

10. **Weak References and Callbacks:** The `WeakCallbackApi`, `NewPersistentHandleFromWeakCallback`, `DoNotUseDeletedNodesInSecondLevelGc`, and `NoGlobalHandlesOrphaningDueToWeakCallback` tests examine V8's weak reference mechanism. Weak references allow holding references to objects without preventing them from being garbage collected. Callbacks are associated with these weak references and are triggered when the referenced object is about to be collected. These tests verify the correct behavior of these callbacks in various scenarios, including creating new persistent handles and triggering garbage collection within callbacks.

11. **Cross-Context Object Literals:** The `CheckForCrossContextObjectLiterals` test checks for issues when working with object literals across different V8 contexts.

12. **Handle Scopes and Contexts:** The `NestedHandleScopeAndContexts` test verifies the correct interaction between nested handle scopes (for managing V8 object lifetimes) and contexts.

13. **JIT Code Event Handling:** The `SetJitCodeEventHandler` test explores V8's API for receiving notifications about JIT-compiled code (`v8::JitCodeEvent`). It sets up an event handler to track when code is added, moved, and when line info recording starts and ends. This test involves simulating memory pressure and garbage collection to trigger code movement.

14. **WebAssembly JIT Code Events:** The `WasmSetJitCodeEventHandler` test (conditional on WebAssembly support) is similar to the previous test but specifically for WebAssembly code.

15. **External Allocated Memory Tracking:** The `ExternalAllocatedMemory` test checks the API for tracking memory allocated outside of V8's heap (`isolate->AdjustAmountOfExternalAllocatedMemory`).

16. **Object Template Embedder Fields:** The `Regress54` test is a regression test that verifies that object templates with embedder fields (data associated with objects created from the template) are handled correctly.

17. **Stack Overflow Handling:** The `CatchStackOverflow` test checks that V8's `TryCatch` mechanism can catch stack overflow errors.

18. **TryCatch Source Information:** The `TryCatchSourceInfo` test verifies that `TryCatch` provides accurate source code information (line number, column, etc.) when exceptions occur in JavaScript code.

**JavaScript Examples:**

*   **Interceptors:**

    ```javascript
    let handler = {
      get(target, prop, receiver) {
        console.log('Getting ' + prop);
        return target[prop];
      },
      set(target, prop, value, receiver) {
        console.log('Setting ' + prop + ' to ' + value);
        target[prop] = value;
        return true;
      }
    };

    let obj = new Proxy({}, handler);
    obj.foo; // "Getting foo" will be logged
    obj.bar = 10; // "Setting bar to 10" will be logged

    // In strict mode, an interceptor can throw an error on set:
    "use strict";
    let strictHandler = {
      set(target, prop, value, receiver) {
        throw new Error("Cannot set property in strict mode");
      }
    };
    let strictObj = new Proxy({}, strictHandler);
    try {
      strictObj.baz = 20; // This will throw an error
    } catch (e) {
      console.error(e);
    }
    ```

*   **Side Effects:**

    ```javascript
    function noSideEffects() {
      return 5;
    }

    let counter = 0;
    function hasSideEffects() {
      counter++;
      return 10;
    }

    noSideEffects(); // This can potentially be optimized away if V8 knows it has no side effects
    hasSideEffects(); // This will always be executed because it modifies the 'counter' variable
    console.log(counter); // Output: 1
    ```

*   **`IsConstructCall` and `NewTarget`:**

    ```javascript
    function MyFunction() {
      console.log('Was called as constructor:', new.target !== undefined);
      if (new.target) {
        this.value = 42;
      }
    }

    MyFunction(); // Output: Was called as constructor: false
    let obj = new MyFunction(); // Output: Was called as constructor: true
    console.log(obj.value); // Output: 42

    class MySubclass extends MyFunction {
      constructor() {
        super();
        console.log('New target in subclass:', new.target); // Will be the MySubclass constructor
      }
    }

    new MySubclass();
    ```

*   **`ObjectProtoToString` and `@@toStringTag`:**

    ```javascript
    let obj = {};
    console.log(obj.toString()); // Output: [object Object]
    console.log(obj[Symbol.toStringTag]); // Output: undefined

    obj[Symbol.toStringTag] = 'MyCustomObject';
    console.log(obj.toString()); // Output: [object MyCustomObject]

    class MyClass {
      get [Symbol.toStringTag]() {
        return 'MyClassInstance';
      }
    }

    let instance = new MyClass();
    console.log(instance.toString()); // Output: [object MyClassInstance]
    ```

*   **`ObjectGetConstructorName` (Less directly mappable to JavaScript, as it's a C++ API):**  In JavaScript, you can get the constructor function using `obj.constructor.name`.

*   **Weak References (Not directly available in standard JavaScript):** Weak references are primarily a feature of the V8 C++ API. While JavaScript has `WeakRef` and `WeakMap`, the C++ API's weak references have slightly different semantics and are used internally by V8.

The code provides a thorough examination of various aspects of the V8 C++ API, particularly focusing on how C++ code interacts with and influences JavaScript execution. The threaded tests and fuzzing highlight the complexities of concurrency within the engine.
This section of the `test-api.cc` file focuses on testing various aspects of the V8 C++ API, particularly how C++ code interacts with JavaScript execution and memory management. Given that it's part 8 of 18, it builds upon concepts tested in previous sections.

Here's a breakdown of the functionalities tested:

**Core API Features and their Interaction with JavaScript:**

*   **Interceptors and Error Handling (`InterceptorShouldThrowOnError`):**  This test examines how **interceptors** (C++ functions that can intercept property access on JavaScript objects) behave in relation to JavaScript's **strict mode** and error handling. It verifies that in strict mode, operations performed through an interceptor can correctly throw JavaScript errors.

    ```javascript
    // JavaScript example related to interceptors and strict mode:
    "use strict";
    let obj = {};
    Object.defineProperty(obj, 'foo', {
      get: function() { return this._foo; },
      set: function(value) {
        if (typeof value !== 'number') {
          throw new TypeError('Value must be a number');
        }
        this._foo = value;
      }
    });

    obj.foo = 10; // Works fine
    try {
      obj.foo = 'abc'; // Throws a TypeError because of the defined setter
    } catch (e) {
      console.error(e);
    }
    ```

*   **Function Call Handlers and Side Effects (`CallHandlerHasNoSideEffect`, `FunctionTemplateNewHasNoSideEffect`, etc.):** These tests explore the concept of **side effects** in function calls. V8 allows marking function call handlers (C++ functions invoked when a JavaScript function is called) as having no side effects. This can be used for optimizations. The tests verify that functions created with this flag behave as expected when evaluated in a context where side effects are disallowed.

    ```javascript
    // JavaScript example related to side effects:
    let counter = 0;

    function hasSideEffect() {
      counter++; // Modifies an external variable (side effect)
      return 5;
    }

    function noSideEffect() {
      return 10; // Only returns a value, no external modifications
    }

    console.log(noSideEffect()); // Can potentially be optimized or evaluated speculatively
    console.log(hasSideEffect()); // Will always be executed because it has a side effect
    console.log(counter); // Output: 1
    ```

*   **`IsConstructCall` (`IsConstructCall`):** This test checks the `IsConstructCall()` method within a function callback. It determines whether the JavaScript function was invoked as a constructor (using `new`).

    ```javascript
    // JavaScript example for IsConstructCall:
    function MyFunction() {
      if (new.target) { // Equivalent to checking IsConstructCall in C++
        console.log("Called as a constructor");
        this.value = 10;
      } else {
        console.log("Called as a regular function");
      }
    }

    MyFunction(); // Output: Called as a regular function
    let obj = new MyFunction(); // Output: Called as a constructor
    console.log(obj.value); // Output: 10
    ```

*   **`NewTarget` (`NewTargetHandler`):** This test verifies the behavior of the `NewTarget()` method in function callbacks. `new.target` in JavaScript provides information about the constructor that was initially invoked, especially useful in inheritance scenarios.

    ```javascript
    // JavaScript example for new.target:
    class Base {
      constructor() {
        console.log("Base's new.target:", new.target);
      }
    }

    class Derived extends Base {
      constructor() {
        super();
        console.log("Derived's new.target:", new.target);
      }
    }

    new Base(); // Output: Base's new.target: class Base
    new Derived(); // Output: Base's new.target: class Derived
                   // Output: Derived's new.target: class Derived
    ```

*   **`ObjectProtoToString` (`ObjectProtoToString`, `ObjectProtoToStringES6`):** These tests examine the `ObjectProtoToString()` API method, which is the C++ equivalent of `Object.prototype.toString()` in JavaScript. They also test how the `@@toStringTag` symbol (introduced in ES6) influences the output of `ObjectProtoToString()`.

    ```javascript
    // JavaScript example for Object.prototype.toString and @@toStringTag:
    let obj = {};
    console.log(obj.toString()); // Output: [object Object]

    obj[Symbol.toStringTag] = 'MyCustomObject';
    console.log(obj.toString()); // Output: [object MyCustomObject]

    class MyClass {
      get [Symbol.toStringTag]() {
        return 'MyClassInstance';
      }
    }
    let instance = new MyClass();
    console.log(instance.toString()); // Output: [object MyClassInstance]
    ```

*   **`ObjectGetConstructorName` (`ObjectGetConstructorName`, `SubclassGetConstructorName`):** These tests verify the `GetConstructorName()` API method, which retrieves the name of the constructor function for a JavaScript object.

    ```javascript
    // JavaScript example for getting constructor name:
    function MyConstructor() {}
    let obj = new MyConstructor();
    console.log(obj.constructor.name); // Output: MyConstructor

    class MyClass {}
    let instance = new MyClass();
    console.log(instance.constructor.name); // Output: MyClass
    ```

*   **Shared Objects (`SharedObjectGetConstructorName`):** This test specifically checks if `GetConstructorName()` works correctly for **shared objects**, a feature in V8 for sharing data between isolates (separate JavaScript execution environments).

**Concurrency and Memory Management:**

*   **Threaded Tests and Fuzzing (`THREADED_TEST`, `ApiTestFuzzer`):** A significant portion introduces a framework for running tests concurrently using threads. The `ApiTestFuzzer` is used to inject randomness and simulate context switching, helping to uncover potential concurrency issues in the V8 API.

*   **Locking (`NestedLockers`, `RecursiveLocking`, `LockUnlockLock`):** These tests examine V8's locking mechanisms (`v8::Locker`, `v8::Unlocker`), ensuring that they function correctly for managing access to V8's internal state in multithreaded scenarios.

*   **Global Object Management (`DontLeakGlobalObjects`):** This test checks for memory leaks related to global JavaScript objects. It verifies that global objects are properly cleaned up when their context is disposed of.

*   **Weak References and Callbacks (`WeakCallbackApi`, `NewPersistentHandleFromWeakCallback`, etc.):** These tests explore V8's **weak reference** mechanism. Weak references allow holding references to JavaScript objects without preventing them from being garbage collected. Callbacks can be associated with weak references to be notified when the referenced object is about to be reclaimed.

*   **External Allocated Memory (`ExternalAllocatedMemory`):** This test checks the API for tracking memory allocated outside of V8's heap using `isolate->AdjustAmountOfExternalAllocatedMemory()`.

**Error Handling and Edge Cases:**

*   **Stack Overflow (`CatchStackOverflow`):** This test verifies that V8 can catch stack overflow errors using `v8::TryCatch`.

*   **TryCatch Source Information (`TryCatchSourceInfo`):** This test ensures that `v8::TryCatch` provides accurate source code location information (line number, column) when a JavaScript exception occurs.

**JIT Code Event Handling (Performance and Debugging):**

*   **JIT Code Event Handler (`SetJitCodeEventHandler`, `WasmSetJitCodeEventHandler`):** These tests explore V8's API for receiving notifications about JIT-compiled code. This is useful for performance analysis and debugging.

**In summary, this part of the `test-api.cc` file thoroughly tests various core functionalities of the V8 C++ API, focusing on how C++ code interacts with JavaScript execution, memory management, and concurrency, as well as how to handle errors and gather debugging information.** The threaded tests and fuzzing highlight the robustness of the API under concurrent conditions. The presence of specific tests like `Regress54` suggests that this section also addresses previously identified bugs or edge cases.

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第8部分，共18部分，请归纳一下它的功能
```

### 源代码
```
.FromJust());
  return v8::Intercepted::kYes;
}

void ShouldThrowOnErrorPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  Local<v8::Array> names = v8::Array::New(isolate, 1);
  CHECK(names->Set(isolate->GetCurrentContext(), names, v8_num(1)).FromJust());
  info.GetReturnValue().Set(names);

  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(),
                  v8_str("should_throw_enumerator"),
                  should_throw_on_error_value)
            .FromJust());
}
}  // namespace

THREADED_TEST(InterceptorShouldThrowOnError) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  auto interceptor_templ = v8::ObjectTemplate::New(isolate);
  v8::NamedPropertyHandlerConfiguration handler(
      ShouldThrowOnErrorGetter, ShouldThrowOnErrorSetter,
      ShouldThrowOnErrorQuery, ShouldThrowOnErrorDeleter,
      ShouldThrowOnErrorPropertyEnumerator);
  interceptor_templ->SetHandler(handler);

  Local<v8::Object> instance =
      interceptor_templ->NewInstance(context.local()).ToLocalChecked();

  CHECK(global->Set(context.local(), v8_str("o"), instance).FromJust());

  // SLOPPY mode
  Local<Value> value = v8_compile("o.f")->Run(context.local()).ToLocalChecked();
  CHECK(value->IsFalse());
  v8_compile("o.f = 153")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_setter"))
              .ToLocalChecked();
  CHECK(value->IsFalse());

  v8_compile("delete o.f")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_deleter"))
              .ToLocalChecked();
  CHECK(value->IsFalse());

  v8_compile("Object.getOwnPropertyNames(o)")
      ->Run(context.local())
      .ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_enumerator"))
              .ToLocalChecked();
  CHECK(value->IsFalse());

  // STRICT mode
  value = v8_compile("'use strict';o.f")->Run(context.local()).ToLocalChecked();
  CHECK(value->IsFalse());
  v8_compile("'use strict'; o.f = 153")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_setter"))
              .ToLocalChecked();
  CHECK(value->IsTrue());

  v8_compile("'use strict'; delete o.f")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_deleter"))
              .ToLocalChecked();
  CHECK(value->IsTrue());

  v8_compile("'use strict'; Object.getOwnPropertyNames(o)")
      ->Run(context.local())
      .ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_enumerator"))
              .ToLocalChecked();
  CHECK(value->IsFalse());
}

static void EmptyHandler(const v8::FunctionCallbackInfo<v8::Value>& args) {}

TEST(CallHandlerHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetCallHandler(EmptyHandler);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("new f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<v8::FunctionTemplate> templ2 = v8::FunctionTemplate::New(isolate);
  templ2->SetCallHandler(EmptyHandler, v8::Local<Value>(),
                         v8::SideEffectType::kHasNoSideEffect);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f2"),
                  templ2->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  v8::debug::EvaluateGlobal(
      isolate, v8_str("new f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

TEST(FunctionTemplateNewHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(isolate, EmptyHandler);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("new f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<v8::FunctionTemplate> templ2 = v8::FunctionTemplate::New(
      isolate, EmptyHandler, v8::Local<Value>(), v8::Local<v8::Signature>(), 0,
      v8::ConstructorBehavior::kAllow, v8::SideEffectType::kHasNoSideEffect);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f2"),
                  templ2->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  v8::debug::EvaluateGlobal(
      isolate, v8_str("new f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

TEST(FunctionTemplateNewWithCacheHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;
  v8::Local<v8::Private> priv =
      v8::Private::ForApi(isolate, v8_str("Foo#draft"));

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::NewWithCache(isolate, EmptyHandler, priv);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("new f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<v8::FunctionTemplate> templ2 = v8::FunctionTemplate::NewWithCache(
      isolate, EmptyHandler, priv, v8::Local<Value>(),
      v8::Local<v8::Signature>(), 0, v8::SideEffectType::kHasNoSideEffect);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f2"),
                  templ2->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  v8::debug::EvaluateGlobal(
      isolate, v8_str("new f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

TEST(FunctionNewHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // Function with side-effect.
  Local<Function> func =
      Function::New(context.local(), EmptyHandler).ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("f"), func).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("new f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<Function> func2 =
      Function::New(context.local(), EmptyHandler, Local<Value>(), 0,
                    v8::ConstructorBehavior::kAllow,
                    v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("f2"), func2).FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  v8::debug::EvaluateGlobal(
      isolate, v8_str("new f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

// These handlers instantiate a function the embedder considers safe in some
// cases (e.g. "building object wrappers"), but those functions themselves were
// not explicitly marked as side-effect-free.
static void DefaultConstructHandler(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Context::Scope context_scope(context);
  v8::MaybeLocal<v8::Object> instance = Function::New(context, EmptyHandler)
                                            .ToLocalChecked()
                                            ->NewInstance(context, 0, nullptr);
  USE(instance);
}

static void NoSideEffectConstructHandler(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Context::Scope context_scope(context);
  v8::MaybeLocal<v8::Object> instance =
      Function::New(context, EmptyHandler)
          .ToLocalChecked()
          ->NewInstanceWithSideEffectType(context, 0, nullptr,
                                          v8::SideEffectType::kHasNoSideEffect);
  USE(instance);
}

static void NoSideEffectAndSideEffectConstructHandler(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Context::Scope context_scope(context);
  // Constructs an instance in a side-effect-free way, followed by another with
  // side effects.
  v8::MaybeLocal<v8::Object> instance =
      Function::New(context, EmptyHandler)
          .ToLocalChecked()
          ->NewInstanceWithSideEffectType(context, 0, nullptr,
                                          v8::SideEffectType::kHasNoSideEffect);
  v8::MaybeLocal<v8::Object> instance2 = Function::New(context, EmptyHandler)
                                             .ToLocalChecked()
                                             ->NewInstance(context, 0, nullptr);
  USE(instance);
  USE(instance2);
}

TEST(FunctionNewInstanceHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // An allowlisted function that creates a new object with both side-effect
  // free/full instantiations. Should throw.
  Local<Function> func0 =
      Function::New(context.local(), NoSideEffectAndSideEffectConstructHandler,
                    Local<Value>(), 0, v8::ConstructorBehavior::kAllow,
                    v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("f"), func0).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // An allowlisted function that creates a new object. Should throw.
  Local<Function> func =
      Function::New(context.local(), DefaultConstructHandler, Local<Value>(), 0,
                    v8::ConstructorBehavior::kAllow,
                    v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("f"), func).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // An allowlisted function that creates a new object with explicit intent to
  // have no side-effects (e.g. building an "object wrapper"). Should not throw.
  Local<Function> func2 =
      Function::New(context.local(), NoSideEffectConstructHandler,
                    Local<Value>(), 0, v8::ConstructorBehavior::kAllow,
                    v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("f2"), func2).FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();

  // Check that side effect skipping did not leak outside to future evaluations.
  Local<Function> func3 =
      Function::New(context.local(), EmptyHandler).ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("f3"), func3).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f3()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Check that using side effect free NewInstance works in normal evaluation
  // (without throwOnSideEffect).
  v8::debug::EvaluateGlobal(isolate, v8_str("f2()"),
                            v8::debug::EvaluateGlobalMode::kDefault)
      .ToLocalChecked();
}

TEST(CallHandlerAsFunctionHasNoSideEffectNotSupported) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // Object template with call as function handler.
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetCallAsFunctionHandler(EmptyHandler);
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("obj()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version is not supported.
  i::Tagged<i::FunctionTemplateInfo> cons = i::Cast<i::FunctionTemplateInfo>(
      v8::Utils::OpenDirectHandle(*templ)->constructor());

  i::Tagged<i::FunctionTemplateInfo> handler =
      i::Cast<i::FunctionTemplateInfo>(cons->GetInstanceCallHandler());
  CHECK(handler->is_object_template_call_handler());
  CHECK(handler->has_side_effects());

  handler->set_has_side_effects(false);
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("obj()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
}

static void IsConstructHandler(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(args.IsConstructCall());
}


THREADED_TEST(IsConstructCall) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetCallHandler(IsConstructHandler);

  LocalContext context;

  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  Local<Value> value = v8_compile("f()")->Run(context.local()).ToLocalChecked();
  CHECK(!value->BooleanValue(isolate));
  value = v8_compile("new f()")->Run(context.local()).ToLocalChecked();
  CHECK(value->BooleanValue(isolate));
}

static void NewTargetHandler(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(args.NewTarget());
}

THREADED_TEST(NewTargetHandler) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetCallHandler(NewTargetHandler);

  LocalContext context;

  Local<Function> function =
      templ->GetFunction(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"), function)
            .FromJust());
  Local<Value> value = CompileRun("f()");
  CHECK(value->IsUndefined());
  value = CompileRun("new f()");
  CHECK(value->IsFunction());
  CHECK(value == function);
  Local<Value> subclass = CompileRun("var g = class extends f { }; g");
  CHECK(subclass->IsFunction());
  value = CompileRun("new g()");
  CHECK(value->IsFunction());
  CHECK(value == subclass);
  value = CompileRun("Reflect.construct(f, [], Array)");
  CHECK(value->IsFunction());
  CHECK(value ==
        context->Global()
            ->Get(context.local(), v8_str("Array"))
            .ToLocalChecked());
}

THREADED_TEST(ObjectProtoToString) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetClassName(v8_str("MyClass"));


  Local<String> customized_tostring = v8_str("customized toString");

  // Replace Object.prototype.toString
  CompileRun(R"(
      Object.prototype.toString = function() {
        return 'customized toString';
      })");

  // Normal ToString call should call replaced Object.prototype.toString
  Local<v8::Object> instance = templ->GetFunction(context.local())
                                   .ToLocalChecked()
                                   ->NewInstance(context.local())
                                   .ToLocalChecked();
  Local<String> value = instance->ToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), customized_tostring).FromJust());

  // ObjectProtoToString should not call replace toString function. It should
  // not look at the class name either.
  value = instance->ObjectProtoToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), v8_str("[object Object]")).FromJust());

  // Check global
  value =
      context->Global()->ObjectProtoToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), v8_str("[object Object]")).FromJust());

  // Check ordinary object
  Local<Value> object = CompileRun("new Object()");
  value = object.As<v8::Object>()
              ->ObjectProtoToString(context.local())
              .ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), v8_str("[object Object]")).FromJust());
}


TEST(ObjectProtoToStringES6) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Check that ES6 semantics using @@toStringTag work.
  Local<v8::Symbol> toStringTag = v8::Symbol::GetToStringTag(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetClassName(v8_str("MyClass"));
  templ->PrototypeTemplate()->Set(
      toStringTag, v8_str("MyClassToStringTag"),
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum));

  Local<String> customized_tostring = v8_str("customized toString");

  // Replace Object.prototype.toString
  CompileRun(R"(
      Object.prototype.toString = function() {
        return 'customized toString';
      })");

  // Normal ToString call should call replaced Object.prototype.toString
  Local<v8::Object> instance = templ->GetFunction(context.local())
                                   .ToLocalChecked()
                                   ->NewInstance(context.local())
                                   .ToLocalChecked();
  Local<String> value = instance->ToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), customized_tostring).FromJust());

  // ObjectProtoToString should not call replace toString function. Instead it
  // should look at the @@toStringTag property.
  value = instance->ObjectProtoToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), v8_str("[object MyClassToStringTag]"))
            .FromJust());

  Local<Value> object;

#define TEST_TOSTRINGTAG(type, tag, expected)                              \
  do {                                                                     \
    object = CompileRun("new " #type "()");                                \
    CHECK(object.As<v8::Object>()                                          \
              ->Set(context.local(), toStringTag, v8_str(#tag))            \
              .FromJust());                                                \
    value = object.As<v8::Object>()                                        \
                ->ObjectProtoToString(context.local())                     \
                .ToLocalChecked();                                         \
    CHECK(value->IsString() &&                                             \
          value->Equals(context.local(), v8_str("[object " #expected "]")) \
              .FromJust());                                                \
  } while (false)

  TEST_TOSTRINGTAG(Array, Object, Object);
  TEST_TOSTRINGTAG(Object, Arguments, Arguments);
  TEST_TOSTRINGTAG(Object, Array, Array);
  TEST_TOSTRINGTAG(Object, Boolean, Boolean);
  TEST_TOSTRINGTAG(Object, Date, Date);
  TEST_TOSTRINGTAG(Object, Error, Error);
  TEST_TOSTRINGTAG(Object, Function, Function);
  TEST_TOSTRINGTAG(Object, Number, Number);
  TEST_TOSTRINGTAG(Object, RegExp, RegExp);
  TEST_TOSTRINGTAG(Object, String, String);
  TEST_TOSTRINGTAG(Object, Foo, Foo);

#undef TEST_TOSTRINGTAG

  Local<v8::RegExp> valueRegExp =
      v8::RegExp::New(context.local(), v8_str("^$"), v8::RegExp::kNone)
          .ToLocalChecked();
  Local<Value> valueNumber = v8_num(123);
  Local<v8::Symbol> valueSymbol = v8_symbol("TestSymbol");
  Local<v8::Function> valueFunction =
      CompileRun("(function fn() {})").As<v8::Function>();
  Local<v8::Object> valueObject = v8::Object::New(isolate);
  Local<v8::Primitive> valueNull = v8::Null(isolate);
  Local<v8::Primitive> valueUndef = v8::Undefined(isolate);

#define TEST_TOSTRINGTAG(type, tagValue, expected)                         \
  do {                                                                     \
    object = CompileRun("new " #type "()");                                \
    CHECK(object.As<v8::Object>()                                          \
              ->Set(context.local(), toStringTag, tagValue)                \
              .FromJust());                                                \
    value = object.As<v8::Object>()                                        \
                ->ObjectProtoToString(context.local())                     \
                .ToLocalChecked();                                         \
    CHECK(value->IsString() &&                                             \
          value->Equals(context.local(), v8_str("[object " #expected "]")) \
              .FromJust());                                                \
  } while (false)

#define TEST_TOSTRINGTAG_TYPES(tagValue)                    \
  TEST_TOSTRINGTAG(Array, tagValue, Array);                 \
  TEST_TOSTRINGTAG(Object, tagValue, Object);               \
  TEST_TOSTRINGTAG(Function, tagValue, Function);           \
  TEST_TOSTRINGTAG(Date, tagValue, Date);                   \
  TEST_TOSTRINGTAG(RegExp, tagValue, RegExp);               \
  TEST_TOSTRINGTAG(Error, tagValue, Error);                 \

  // Test non-String-valued @@toStringTag
  TEST_TOSTRINGTAG_TYPES(valueRegExp);
  TEST_TOSTRINGTAG_TYPES(valueNumber);
  TEST_TOSTRINGTAG_TYPES(valueSymbol);
  TEST_TOSTRINGTAG_TYPES(valueFunction);
  TEST_TOSTRINGTAG_TYPES(valueObject);
  TEST_TOSTRINGTAG_TYPES(valueNull);
  TEST_TOSTRINGTAG_TYPES(valueUndef);

#undef TEST_TOSTRINGTAG
#undef TEST_TOSTRINGTAG_TYPES

  // @@toStringTag getter throws
  Local<Value> obj = v8::Object::New(isolate);
  obj.As<v8::Object>()
      ->SetNativeDataProperty(context.local(), toStringTag,
                              ThrowingSymbolAccessorGetter)
      .FromJust();
  {
    TryCatch try_catch(isolate);
    CHECK(obj.As<v8::Object>()->ObjectProtoToString(context.local()).IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  // @@toStringTag getter does not throw
  obj = v8::Object::New(isolate);
  obj.As<v8::Object>()
      ->SetNativeDataProperty(context.local(), toStringTag,
                              SymbolAccessorGetterReturnsDefault, nullptr,
                              v8_str("Test"))
      .FromJust();
  {
    TryCatch try_catch(isolate);
    value = obj.As<v8::Object>()
                ->ObjectProtoToString(context.local())
                .ToLocalChecked();
    CHECK(value->IsString() &&
          value->Equals(context.local(), v8_str("[object Test]")).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  // JS @@toStringTag value
  obj = CompileRun("obj = {}; obj[Symbol.toStringTag] = 'Test'; obj");
  {
    TryCatch try_catch(isolate);
    value = obj.As<v8::Object>()
                ->ObjectProtoToString(context.local())
                .ToLocalChecked();
    CHECK(value->IsString() &&
          value->Equals(context.local(), v8_str("[object Test]")).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  // JS @@toStringTag getter throws
  obj = CompileRun(
      "obj = {}; Object.defineProperty(obj, Symbol.toStringTag, {"
      "  get: function() { throw 'Test'; }"
      "}); obj");
  {
    TryCatch try_catch(isolate);
    CHECK(obj.As<v8::Object>()->ObjectProtoToString(context.local()).IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  // JS @@toStringTag getter does not throw
  obj = CompileRun(
      "obj = {}; Object.defineProperty(obj, Symbol.toStringTag, {"
      "  get: function() { return 'Test'; }"
      "}); obj");
  {
    TryCatch try_catch(isolate);
    value = obj.As<v8::Object>()
                ->ObjectProtoToString(context.local())
                .ToLocalChecked();
    CHECK(value->IsString() &&
          value->Equals(context.local(), v8_str("[object Test]")).FromJust());
    CHECK(!try_catch.HasCaught());
  }
}

namespace {

void CheckGetConstructorNameOfVar(LocalContext& context, const char* var_name,
                                  const char* constructor_name) {
  Local<v8::Value> var = context->Global()
                             ->Get(context.local(), v8_str(var_name))
                             .ToLocalChecked();
  CHECK(var->IsObject() &&
        var->ToObject(context.local())
            .ToLocalChecked()
            ->GetConstructorName()
            ->Equals(context.local(), v8_str(constructor_name))
            .FromJust());
}

}  // namespace

THREADED_TEST(ObjectGetConstructorName) {
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext context;
  v8::HandleScope scope(isolate);
  v8_compile(
      "function Parent() {};"
      "function Child() {};"
      "Child.prototype = new Parent();"
      "Child.prototype.constructor = Child;"
      "var outer = { inner: (0, function() { }) };"
      "var p = new Parent();"
      "var c = new Child();"
      "var x = new outer.inner();"
      "var proto = Child.prototype;")
      ->Run(context.local())
      .ToLocalChecked();

  CheckGetConstructorNameOfVar(context, "p", "Parent");
  CheckGetConstructorNameOfVar(context, "c", "Child");
  CheckGetConstructorNameOfVar(context, "x", "outer.inner");
  CheckGetConstructorNameOfVar(context, "proto", "Parent");
}


THREADED_TEST(SubclassGetConstructorName) {
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext context;
  v8::HandleScope scope(isolate);
  v8_compile(
      "\"use strict\";"
      "class Parent {}"
      "class Child extends Parent {}"
      "var p = new Parent();"
      "var c = new Child();")
      ->Run(context.local())
      .ToLocalChecked();

  CheckGetConstructorNameOfVar(context, "p", "Parent");
  CheckGetConstructorNameOfVar(context, "c", "Child");
}

UNINITIALIZED_TEST(SharedObjectGetConstructorName) {
  if (!V8_CAN_CREATE_SHARED_HEAP_BOOL) return;
  // In multi-cage mode we create one cage per isolate
  // and we don't share objects between cages.
  if (COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL) return;

  i::v8_flags.shared_string_table = true;
  i::v8_flags.harmony_struct = true;
  i::FlagList::EnforceFlagImplications();

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope scope(isolate);
    LocalContext context(isolate);

    v8_compile(
        "var s = new (new SharedStructType(['foo']));"
        "var a = new SharedArray(1);"
        "var m = new Atomics.Mutex;"
        "var c = new Atomics.Condition;")
        ->Run(context.local())
        .ToLocalChecked();

    CheckGetConstructorNameOfVar(context, "s", "SharedStruct");
    CheckGetConstructorNameOfVar(context, "a", "SharedArray");
    CheckGetConstructorNameOfVar(context, "m", "Atomics.Mutex");
    CheckGetConstructorNameOfVar(context, "c", "Atomics.Condition");
  }
  isolate->Dispose();
}

unsigned ApiTestFuzzer::linear_congruential_generator;
std::vector<std::unique_ptr<ApiTestFuzzer>> ApiTestFuzzer::fuzzers_;
bool ApiTestFuzzer::fuzzing_ = false;
v8::base::Semaphore ApiTestFuzzer::all_tests_done_(0);
int ApiTestFuzzer::tests_being_run_;
int ApiTestFuzzer::active_tests_;
int ApiTestFuzzer::current_fuzzer_;

// We are in a callback and want to switch to another thread (if we
// are currently running the thread fuzzing test).
void ApiTestFuzzer::Fuzz() {
  // Emulate context switch which might cause side effects as well.
  // This is mostly to ensure that the callbacks in the tests do not cause
  // side effects when they don't intercept the operation.
  CcTest::i_isolate()->IncrementJavascriptExecutionCounter();

  if (!fuzzing_) return;
  fuzzers_[current_fuzzer_]->ContextSwitch();
}


// Let the next thread go.  Since it is also waiting on the V8 lock it may
// not start immediately.
bool ApiTestFuzzer::NextThread() {
  int next_fuzzer = GetNextFuzzer();
  if (next_fuzzer == current_fuzzer_) {
    if (kLogThreading) {
      int current_number = fuzzers_[current_fuzzer_]->test_number_;
      printf("Stay with %s #%d\n",
             RegisterThreadedTest::nth(current_number)->name(), current_number);
    }
    return false;
  }
  if (kLogThreading) {
    int current_number =
        current_fuzzer_ >= 0 ? fuzzers_[current_fuzzer_]->test_number_ : -1;
    int next_number = fuzzers_[next_fuzzer]->test_number_;
    printf("Switch from %s #%d to %s #%d\n",
           current_number >= 0
               ? RegisterThreadedTest::nth(current_number)->name()
               : "<none>",
           current_number, RegisterThreadedTest::nth(next_number)->name(),
           next_number);
  }
  current_fuzzer_ = next_fuzzer;
  fuzzers_[current_fuzzer_]->gate_.Signal();
  return true;
}

void ApiTestFuzzer::Run() {
  // Wait until it is our turn.
  gate_.Wait();
  {
    // Get the V8 lock.
    v8::Locker locker(CcTest::isolate());
    // Start running the test, which will enter the isolate and exit it when it
    // finishes.
    CallTest();
  }
  // This test finished.
  active_ = false;
  active_tests_--;
  // If it was the last then signal that fact.
  if (active_tests_ == 0) {
    all_tests_done_.Signal();
  } else {
    // Otherwise select a new test and start that.
    NextThread();
  }
}

void ApiTestFuzzer::SetUp(PartOfTest part) {
  linear_congruential_generator = i::v8_flags.testing_prng_seed;
  fuzzing_ = true;
  int count = RegisterThreadedTest::count();
  int start =  count * part / (LAST_PART + 1);
  int end = (count * (part + 1) / (LAST_PART + 1)) - 1;
  active_tests_ = tests_being_run_ = end - start + 1;
  fuzzers_.clear();
  for (int i = 0; i < tests_being_run_; i++) {
    fuzzers_.push_back(
        std::unique_ptr<ApiTestFuzzer>(new ApiTestFuzzer(i + start)));
  }
  for (const auto& fuzzer : fuzzers_) {
    CHECK(fuzzer->Start());
  }
}

void ApiTestFuzzer::RunAllTests() {
  // This method is called when running each THREADING_TEST, which is an
  // initialized test and has entered the isolate at this point. We need to exit
  // the isolate, so that the fuzzer threads can enter it in turn, while running
  // their tests.
  CcTest::isolate()->Exit();
  // Set off the first test.
  current_fuzzer_ = -1;
  NextThread();
  // Wait till they are all done.
  all_tests_done_.Wait();
  // We enter the isolate again, to prepare for teardown.
  CcTest::isolate()->Enter();
}

int ApiTestFuzzer::GetNextFuzzer() {
  int next;
  do {
    next = (linear_congruential_generator >> 16) % tests_being_run_;
    linear_congruential_generator *= 1664525u;
    linear_congruential_generator += 1013904223u;
  } while (!fuzzers_[next]->active_);
  return next;
}

void ApiTestFuzzer::ContextSwitch() {
  // If the new thread is the same as the current thread there is nothing to do.
  if (!NextThread()) return;
  // Mark the stack of this background thread for conservative stack scanning.
  CcTest::i_isolate()->heap()->stack().SetMarkerForBackgroundThreadAndCallback(
      i::ThreadId::Current().ToInteger(), [this]() {
        // Exit the isolate from this thread.
        CcTest::i_isolate()->Exit();
        {
          // Now the new thread can start.
          v8::Unlocker unlocker(CcTest::isolate());
          // Wait till someone starts us again.
          gate_.Wait();
        }
        // Enter the isolate from this thread again.
        CcTest::i_isolate()->Enter();
        // And we're off.
      });
}

void ApiTestFuzzer::TearDown() {
  fuzzing_ = false;
  for (const auto& fuzzer : fuzzers_) {
    if (fuzzer) fuzzer->Join();
  }
}

void ApiTestFuzzer::CallTest() {
  v8::Isolate::Scope scope(CcTest::isolate());
  if (kLogThreading)
    printf("Start test %s #%d\n",
           RegisterThreadedTest::nth(test_number_)->name(), test_number_);
  (RegisterThreadedTest::nth(test_number_)->callback())();
  if (kLogThreading)
    printf("End test %s #%d\n", RegisterThreadedTest::nth(test_number_)->name(),
           test_number_);
}

#define THREADING_TEST(INDEX, NAME)            \
  TEST(Threading##INDEX) {                     \
    ApiTestFuzzer::SetUp(ApiTestFuzzer::NAME); \
    ApiTestFuzzer::RunAllTests();              \
    ApiTestFuzzer::TearDown();                 \
  }

THREADING_TEST(1, FIRST_PART)
THREADING_TEST(2, SECOND_PART)
THREADING_TEST(3, THIRD_PART)
THREADING_TEST(4, FOURTH_PART)
THREADING_TEST(5, FIFTH_PART)
THREADING_TEST(6, SIXTH_PART)
THREADING_TEST(7, SEVENTH_PART)
THREADING_TEST(8, EIGHTH_PART)

#undef THREADING_TEST

static void ThrowInJS(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Isolate* isolate = args.GetIsolate();
  CHECK(v8::Locker::IsLocked(isolate));
  ApiTestFuzzer::Fuzz();
  v8::Unlocker unlocker(isolate);
  const char* code = "throw 7;";
  {
    v8::Locker nested_locker(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<Value> exception;
    {
      v8::TryCatch try_catch(isolate);
      v8::Local<Value> value = CompileRun(code);
      CHECK(value.IsEmpty());
      CHECK(try_catch.HasCaught());
      // Make sure to wrap the exception in a new handle because
      // the handle returned from the TryCatch is destroyed
      // when the TryCatch is destroyed.
      exception = Local<Value>::New(isolate, try_catch.Exception());
    }
    args.GetIsolate()->ThrowException(exception);
  }
}


static void ThrowInJSNoCatch(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(v8::Locker::IsLocked(CcTest::isolate()));
  ApiTestFuzzer::Fuzz();
  v8::Unlocker unlocker(CcTest::isolate());
  const char* code = "throw 7;";
  {
    v8::Locker nested_locker(CcTest::isolate());
    v8::HandleScope scope(args.GetIsolate());
    v8::Local<Value> value = CompileRun(code);
    CHECK(value.IsEmpty());
    args.GetReturnValue().Set(v8_str("foo"));
  }
}


// These are locking tests that don't need to be run again
// as part of the locking aggregation tests.
TEST(NestedLockers) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Locker locker(isolate);
  CHECK(v8::Locker::IsLocked(isolate));
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(isolate, ThrowInJS);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("throw_in_js"), fun).FromJust());
  Local<Script> script = v8_compile("(function () {"
                                    "  try {"
                                    "    throw_in_js();"
                                    "    return 42;"
                                    "  } catch (e) {"
                                    "    return e * 13;"
                                    "  }"
                                    "})();");
  CHECK_EQ(91, script->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}


// These are locking tests that don't need to be run again
// as part of the locking aggregation tests.
TEST(NestedLockersNoTryCatch) {
  v8::Locker locker(CcTest::isolate());
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(env->GetIsolate(), ThrowInJSNoCatch);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("throw_in_js"), fun).FromJust());
  Local<Script> script = v8_compile("(function () {"
                                    "  try {"
                                    "    throw_in_js();"
                                    "    return 42;"
                                    "  } catch (e) {"
                                    "    return e * 13;"
                                    "  }"
                                    "})();");
  CHECK_EQ(91, script->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}


THREADED_TEST(RecursiveLocking) {
  v8::Locker locker(CcTest::isolate());
  {
    v8::Locker locker2(CcTest::isolate());
    CHECK(v8::Locker::IsLocked(CcTest::isolate()));
  }
}


static void UnlockForAMoment(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  v8::Unlocker unlocker(CcTest::isolate());
}


THREADED_TEST(LockUnlockLock) {
  {
    v8::Locker locker(CcTest::isolate());
    v8::HandleScope scope(CcTest::isolate());
    LocalContext env;
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(CcTest::isolate(), UnlockForAMoment);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("unlock_for_a_moment"), fun)
              .FromJust());
    Local<Script> script = v8_compile("(function () {"
                                      "  unlock_for_a_moment();"
                                      "  return 42;"
                                      "})();");
    CHECK_EQ(42, script->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }
  {
    v8::Locker locker(CcTest::isolate());
    v8::HandleScope scope(CcTest::isolate());
    LocalContext env;
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(CcTest::isolate(), UnlockForAMoment);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("unlock_for_a_moment"), fun)
              .FromJust());
    Local<Script> script = v8_compile("(function () {"
                                      "  unlock_for_a_moment();"
                                      "  return 42;"
                                      "})();");
    CHECK_EQ(42, script->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }
}


static int GetGlobalObjectsCount() {
  int count = 0;
  i::HeapObjectIterator it(CcTest::heap());
  for (i::Tagged<i::HeapObject> object = it.Next(); !object.is_null();
       object = it.Next()) {
    if (IsJSGlobalObject(object)) {
      i::Tagged<i::JSGlobalObject> g = i::Cast<i::JSGlobalObject>(object);
      // Skip dummy global object.
      if (g->global_dictionary(v8::kAcquireLoad)->NumberOfElements() != 0) {
        count++;
      }
    }
  }
  return count;
}


static void CheckSurvivingGlobalObjectsCount(int expected) {
  // We need to invoke GC without stack, otherwise some objects may not be
  // cleared because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());
  // We need to collect all garbage twice to be sure that everything
  // has been collected.  This is because inline caches are cleared in
  // the first garbage collection but some of the maps have already
  // been marked at that point.  Therefore some of the maps are not
  // collected until the second garbage collection.
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
  int count = GetGlobalObjectsCount();
  CHECK_EQ(expected, count);
}


TEST(DontLeakGlobalObjects) {
  // Regression test for issues 1139850 and 1174891.
  i::v8_flags.expose_gc = true;

  for (int i = 0; i < 5; i++) {
    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
    }
    CcTest::isolate()->ContextDisposedNotification();
    CheckSurvivingGlobalObjectsCount(0);

    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
      v8_compile("Date")->Run(context.local()).ToLocalChecked();
    }
    CcTest::isolate()->ContextDisposedNotification();
    CheckSurvivingGlobalObjectsCount(0);

    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
      v8_compile("/aaa/")->Run(context.local()).ToLocalChecked();
    }
    CcTest::isolate()->ContextDisposedNotification();
    CheckSurvivingGlobalObjectsCount(0);

    { v8::HandleScope scope(CcTest::isolate());
      const char* extension_list[] = { "v8/gc" };
      v8::ExtensionConfiguration extensions(1, extension_list);
      LocalContext context(&extensions);
      v8_compile("gc();")->Run(context.local()).ToLocalChecked();
    }
    CcTest::isolate()->ContextDisposedNotification();
    CheckSurvivingGlobalObjectsCount(0);
  }
}

static void WeakApiCallback(
    const v8::WeakCallbackInfo<Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
  delete data.GetParameter();
}


TEST(WeakCallbackApi) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  i::GlobalHandles* globals =
      reinterpret_cast<i::Isolate*>(isolate)->global_handles();
  size_t initial_handles = globals->handles_count();
  {
    v8::HandleScope scope(isolate);
    v8::Local<v8::Object> obj = v8::Object::New(isolate);
    CHECK(
        obj->Set(context.local(), v8_str("key"), v8::Integer::New(isolate, 231))
            .FromJust());
    v8::Persistent<v8::Object>* handle =
        new v8::Persistent<v8::Object>(isolate, obj);
    handle->SetWeak<v8::Persistent<v8::Object>>(
        handle, WeakApiCallback, v8::WeakCallbackType::kParameter);
  }
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }
  // Verify disposed.
  CHECK_EQ(initial_handles, globals->handles_count());
}

v8::Persistent<v8::Object> some_object;
v8::Persistent<v8::Object> bad_handle;


void NewPersistentHandleCallback2(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  v8::HandleScope scope(data.GetIsolate());
  bad_handle.Reset(data.GetIsolate(), some_object);
}


void NewPersistentHandleCallback1(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
  data.SetSecondPassCallback(NewPersistentHandleCallback2);
}

TEST(NewPersistentHandleFromWeakCallback) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();

  v8::Persistent<v8::Object> handle1, handle2;
  {
    v8::HandleScope scope(isolate);
    some_object.Reset(isolate, v8::Object::New(isolate));
    handle1.Reset(isolate, v8::Object::New(isolate));
    handle2.Reset(isolate, v8::Object::New(isolate));
  }
  // Note: order is implementation dependent alas: currently
  // global handle nodes are processed by PostGarbageCollectionProcessing
  // in reverse allocation order, so if second allocated handle is deleted,
  // weak callback of the first handle would be able to 'reallocate' it.
  handle1.SetWeak(&handle1, NewPersistentHandleCallback1,
                  v8::WeakCallbackType::kParameter);
  handle2.Reset();
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared by this GC because of conservative stack scanning and, when
    // it is cleared, the handle object will be dead and the pointer passed
    // as parameter to the callback will be dangling.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
}

v8::Persistent<v8::Object> to_be_disposed;


void DisposeAndForceGcCallback2(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  to_be_disposed.Reset();
  i::heap::InvokeMajorGC(CcTest::heap());
}


void DisposeAndForceGcCallback1(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
  data.SetSecondPassCallback(DisposeAndForceGcCallback2);
}

TEST(DoNotUseDeletedNodesInSecondLevelGc) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();

  v8::Persistent<v8::Object> handle1, handle2;
  {
    v8::HandleScope scope(isolate);
    handle1.Reset(isolate, v8::Object::New(isolate));
    handle2.Reset(isolate, v8::Object::New(isolate));
  }
  handle1.SetWeak(&handle1, DisposeAndForceGcCallback1,
                  v8::WeakCallbackType::kParameter);
  to_be_disposed.Reset(isolate, handle2);
  {
    // We need to invoke GC without stack, otherwise the weak reference may not
    // be cleared by this GC because of conservative stack scanning and, when
    // it is cleared, the handle object will be dead and the pointer passed
    // as parameter to the callback will be dangling.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
}

void DisposingCallback(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
}

void HandleCreatingCallback2(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  v8::HandleScope scope(data.GetIsolate());
  v8::Global<v8::Object>(data.GetIsolate(), v8::Object::New(data.GetIsolate()));
}


void HandleCreatingCallback1(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  data.GetParameter()->Reset();
  data.SetSecondPassCallback(HandleCreatingCallback2);
}

TEST(NoGlobalHandlesOrphaningDueToWeakCallback) {
  v8::Locker locker(CcTest::isolate());
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();

  v8::Persistent<v8::Object> handle1, handle2, handle3;
  {
    v8::HandleScope scope(isolate);
    handle3.Reset(isolate, v8::Object::New(isolate));
    handle2.Reset(isolate, v8::Object::New(isolate));
    handle1.Reset(isolate, v8::Object::New(isolate));
  }
  handle2.SetWeak(&handle2, DisposingCallback,
                  v8::WeakCallbackType::kParameter);
  handle3.SetWeak(&handle3, HandleCreatingCallback1,
                  v8::WeakCallbackType::kParameter);
  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared by this GC because of conservative stack scanning and, when
    // they are cleared, the handle objects will be dead and the pointers passed
    // as parameters to the callbacks will be dangling.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  EmptyMessageQueues(isolate);
}

THREADED_TEST(CheckForCrossContextObjectLiterals) {
  const int nof = 2;
  const char* sources[nof] = {
    "try { [ 2, 3, 4 ].forEach(5); } catch(e) { e.toString(); }",
    "Object()"
  };

  for (int i = 0; i < nof; i++) {
    const char* source = sources[i];
    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
      CompileRun(source);
    }
    { v8::HandleScope scope(CcTest::isolate());
      LocalContext context;
      CompileRun(source);
    }
  }
}

static v8::Local<Value> NestedScope(v8::Local<Context> env) {
  v8::EscapableHandleScope inner(env->GetIsolate());
  env->Enter();
  v8::Local<Value> three = v8_num(3);
  v8::Local<Value> value = inner.Escape(three);
  env->Exit();
  return value;
}


THREADED_TEST(NestedHandleScopeAndContexts) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope outer(isolate);
  v8::Local<Context> env = Context::New(isolate);
  env->Enter();
  v8::Local<Value> value = NestedScope(env);
  v8::Local<String> str(value->ToString(env).ToLocalChecked());
  CHECK(!str.IsEmpty());
  env->Exit();
}

namespace {
static v8::base::HashMap* instruction_stream_map = nullptr;
static v8::base::HashMap* jitcode_line_info = nullptr;
static int saw_bar = 0;
static int move_events = 0;

static bool FunctionNameIs(const char* expected,
                           const v8::JitCodeEvent* event) {
  // Log lines for functions are of the general form:
  // "JS:<type><function_name>" or Function:<type><function_name>,
  // where the type is one of "*", "~" or "".
  static const char* kPreamble = "JS:";
  static size_t kPreambleLen = strlen(kPreamble);

  if (event->name.len < kPreambleLen ||
      strncmp(kPreamble, event->name.str, kPreambleLen) != 0) {
    return false;
  }

  const char* tail = event->name.str + kPreambleLen;
  size_t tail_len = event->name.len - kPreambleLen;
  size_t expected_len = strlen(expected);
  if (tail_len > 1 && (*tail == '*' || *tail == '~')) {
    --tail_len;
    ++tail;
  }

  // Check for tails like 'bar :1'.
  if (tail_len > expected_len + 2 &&
      tail[expected_len] == ' ' &&
      tail[expected_len + 1] == ':' &&
      tail[expected_len + 2] &&
      !strncmp(tail, expected, expected_len)) {
    return true;
  }

  if (tail_len != expected_len)
    return false;

  return strncmp(tail, expected, expected_len) == 0;
}

static void event_handler(const v8::JitCodeEvent* event) {
  CHECK_NOT_NULL(event);
  CHECK_NOT_NULL(instruction_stream_map);
  CHECK_NOT_NULL(jitcode_line_info);

  class DummyJitCodeLineInfo {
  };

  switch (event->type) {
    case v8::JitCodeEvent::CODE_ADDED: {
      CHECK_NOT_NULL(event->code_start);
      CHECK_NE(0, static_cast<int>(event->code_len));
      CHECK_NOT_NULL(event->name.str);
      v8::base::HashMap::Entry* entry = instruction_stream_map->LookupOrInsert(
          event->code_start, i::ComputePointerHash(event->code_start));
      entry->value = reinterpret_cast<void*>(event->code_len);

      if (FunctionNameIs("bar", event)) {
        ++saw_bar;
        }
      }
      break;

    case v8::JitCodeEvent::CODE_MOVED: {
        uint32_t hash = i::ComputePointerHash(event->code_start);
        // We would like to never see code move that we haven't seen before,
        // but the code creation event does not happen until the line endings
        // have been calculated (this is so that we can report the line in the
        // script at which the function source is found, see
        // Compiler::RecordFunctionCompilation) and the line endings
        // calculations can cause a GC, which can move the newly created code
        // before its existence can be logged.
        v8::base::HashMap::Entry* entry =
            instruction_stream_map->Lookup(event->code_start, hash);
        if (entry != nullptr) {
          ++move_events;

          CHECK_EQ(reinterpret_cast<void*>(event->code_len), entry->value);
          instruction_stream_map->Remove(event->code_start, hash);

          entry = instruction_stream_map->LookupOrInsert(
              event->new_code_start,
              i::ComputePointerHash(event->new_code_start));
          entry->value = reinterpret_cast<void*>(event->code_len);
        }
      }
      break;

    case v8::JitCodeEvent::CODE_REMOVED:
      // Object/code removal events are currently not dispatched from the GC.
      UNREACHABLE();

    // For CODE_START_LINE_INFO_RECORDING event, we will create one
    // DummyJitCodeLineInfo data structure pointed by event->user_dat. We
    // record it in jitcode_line_info.
    case v8::JitCodeEvent::CODE_START_LINE_INFO_RECORDING: {
        DummyJitCodeLineInfo* line_info = new DummyJitCodeLineInfo();
        v8::JitCodeEvent* temp_event = const_cast<v8::JitCodeEvent*>(event);
        temp_event->user_data = line_info;
        v8::base::HashMap::Entry* entry = jitcode_line_info->LookupOrInsert(
            line_info, i::ComputePointerHash(line_info));
        entry->value = reinterpret_cast<void*>(line_info);
      }
      break;
    // For these two events, we will check whether the event->user_data
    // data structure is created before during CODE_START_LINE_INFO_RECORDING
    // event. And delete it in CODE_END_LINE_INFO_RECORDING event handling.
    case v8::JitCodeEvent::CODE_END_LINE_INFO_RECORDING: {
      CHECK_NOT_NULL(event->user_data);
      uint32_t hash = i::ComputePointerHash(event->user_data);
      v8::base::HashMap::Entry* entry =
          jitcode_line_info->Lookup(event->user_data, hash);
      CHECK_NOT_NULL(entry);
      delete reinterpret_cast<DummyJitCodeLineInfo*>(event->user_data);
      }
      break;

    case v8::JitCodeEvent::CODE_ADD_LINE_POS_INFO: {
      CHECK_NOT_NULL(event->user_data);
      uint32_t hash = i::ComputePointerHash(event->user_data);
      v8::base::HashMap::Entry* entry =
          jitcode_line_info->Lookup(event->user_data, hash);
      CHECK_NOT_NULL(entry);
      }
      break;

    default:
      // Impossible event.
      UNREACHABLE();
  }
}
}  // namespace

UNINITIALIZED_TEST(SetJitCodeEventHandler) {
  i::v8_flags.stress_compaction = true;
  i::v8_flags.incremental_marking = false;
  i::v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  // Batch compilation can cause different owning spaces for foo and bar.
#ifdef V8_ENABLE_SPARKPLUG
  i::v8_flags.baseline_batch_compilation = false;
#endif
  if (!i::v8_flags.compact) return;
  i::FlagList::EnforceFlagImplications();
  const char* script =
      "function bar() {"
      "  var sum = 0;"
      "  for (i = 0; i < 10; ++i)"
      "    sum = foo(i);"
      "  return sum;"
      "}"
      "function foo(i) { return i; };"
      "bar();";

  // Run this test in a new isolate to make sure we don't
  // have remnants of state from other code.
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::Heap* heap = i_isolate->heap();

  // Start with a clean slate.
  i::heap::InvokeMemoryReducingMajorGCs(heap);
  {
    v8::HandleScope scope(isolate);
    v8::base::HashMap code;
    instruction_stream_map = &code;

    v8::base::HashMap lineinfo;
    jitcode_line_info = &lineinfo;

    saw_bar = 0;
    move_events = 0;

    isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, event_handler);

    // Generate new code objects sparsely distributed across several
    // different fragmented code-space pages.
    const int kIterations = 10;
    for (int i = 0; i < kIterations; ++i) {
      LocalContext env(isolate);
      i::AlwaysAllocateScopeForTesting always_allocate(heap);
      CompileRun(script);

      // Keep a strong reference to the code object in the handle scope.
      i::DirectHandle<i::JSFunction> bar = i::Cast<i::JSFunction>(
          v8::Utils::OpenHandle(*env->Global()
                                     ->Get(env.local(), v8_str("bar"))
                                     .ToLocalChecked()));
      i::DirectHandle<i::JSFunction> foo = i::Cast<i::JSFunction>(
          v8::Utils::OpenHandle(*env->Global()
                                     ->Get(env.local(), v8_str("foo"))
                                     .ToLocalChecked()));

      i::PagedSpace* foo_owning_space = reinterpret_cast<i::PagedSpace*>(
          i::PageMetadata::FromHeapObject(foo->abstract_code(i_isolate))
              ->owner());
      i::PagedSpace* bar_owning_space = reinterpret_cast<i::PagedSpace*>(
          i::PageMetadata::FromHeapObject(bar->abstract_code(i_isolate))
              ->owner());

      CHECK_EQ(foo_owning_space, bar_owning_space);
      i::heap::SimulateFullSpace(foo_owning_space);

      // Clear the compilation cache to get more wastage.
      reinterpret_cast<i::Isolate*>(isolate)->compilation_cache()->Clear();
    }

    // Force code movement.
    {
      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
          heap);
      i::heap::InvokeMemoryReducingMajorGCs(heap);
    }

    isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, nullptr);

    CHECK_LE(kIterations, saw_bar);
    CHECK_LT(0, move_events);

    instruction_stream_map = nullptr;
    jitcode_line_info = nullptr;
  }

  isolate->Exit();
  isolate->Dispose();

  // Do this in a new isolate.
  isolate = v8::Isolate::New(create_params);
  isolate->Enter();

  // Verify that we get callbacks for existing code objects when we
  // request enumeration of existing code.
  {
    v8::HandleScope scope(isolate);
    LocalContext env(isolate);
    CompileRun(script);

    // Now get code through initial iteration.
    v8::base::HashMap code;
    instruction_stream_map = &code;

    v8::base::HashMap lineinfo;
    jitcode_line_info = &lineinfo;

    isolate->SetJitCodeEventHandler(v8::kJitCodeEventEnumExisting,
                                    event_handler);
    isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, nullptr);

    jitcode_line_info = nullptr;
    // We expect that we got some events. Note that if we could get code removal
    // notifications, we could compare two collections, one created by listening
    // from the time of creation of an isolate, and the other by subscribing
    // with EnumExisting.
    CHECK_LT(0u, code.occupancy());

    instruction_stream_map = nullptr;
  }

  isolate->Exit();
  isolate->Dispose();
}

#if V8_ENABLE_WEBASSEMBLY
static bool saw_wasm_main = false;
static void wasm_event_handler(const v8::JitCodeEvent* event) {
  switch (event->type) {
    case v8::JitCodeEvent::CODE_ADDED: {
      if (FunctionNameIs("main-0-turbofan", event)) {
        saw_wasm_main = true;
        // Make sure main function has line info.
        auto* entry = jitcode_line_info->Lookup(
            event->code_start, i::ComputePointerHash(event->code_start));
        CHECK_NOT_NULL(entry);
      }
      break;
    }
    case v8::JitCodeEvent::CODE_END_LINE_INFO_RECORDING: {
      jitcode_line_info->LookupOrInsert(
          event->code_start, i::ComputePointerHash(event->code_start));
      break;
    }
    case v8::JitCodeEvent::CODE_ADD_LINE_POS_INFO: {
      break;
    }
    default: {
      // Ignore all other events;
    }
  }
}

namespace v8::internal::wasm {
TEST(WasmSetJitCodeEventHandler) {
  v8::base::HashMap code;
  instruction_stream_map = &code;

  v8::base::HashMap lineinfo;
  jitcode_line_info = &lineinfo;

  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  i::Isolate* isolate = r.main_isolate();

  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8_isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault,
                                     wasm_event_handler);

  // Add (unreached) endless recursion to prevent fully inling "f". Otherwise we
  // won't have source positions and will miss the
  // {CODE_END_LINE_INFO_RECORDING} event.
  TestSignatures sigs;
  auto& f = r.NewFunction(sigs.i_i(), "f");
  f.Build({WASM_IF(WASM_I32_EQZ(WASM_LOCAL_GET(0)),
                   WASM_LOCAL_SET(0, WASM_CALL_FUNCTION(f.function_index(),
                                                        WASM_LOCAL_GET(0)))),
           WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});

  LocalContext env;

  r.Build(
      {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_CALL_FUNCTION(f.function_index(),
                                                          WASM_LOCAL_GET(1)))});

  Handle<JSFunction> func = r.builder().WrapCode(0);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("func"), v8::Utils::ToLocal(func))
            .FromJust());
  const char* script = R"(
    func(1, 2);
  )";
  CompileRun(script);
  CHECK(saw_wasm_main);
}
}  // namespace v8::internal::wasm
#endif  // V8_ENABLE_WEBASSEMBLY

TEST(ExternalAllocatedMemory) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope outer(isolate);
  v8::Local<Context> env(Context::New(isolate));
  CHECK(!env.IsEmpty());
  const int64_t kSize = 1024*1024;
  int64_t baseline = isolate->AdjustAmountOfExternalAllocatedMemory(0);
  CHECK_EQ(baseline + kSize,
           isolate->AdjustAmountOfExternalAllocatedMemory(kSize));
  CHECK_EQ(baseline,
           isolate->AdjustAmountOfExternalAllocatedMemory(-kSize));
  const int64_t kTriggerGCSize =
      CcTest::i_isolate()->heap()->external_memory_hard_limit() + 1;
  CHECK_EQ(baseline + kTriggerGCSize,
           isolate->AdjustAmountOfExternalAllocatedMemory(kTriggerGCSize));
  CHECK_EQ(baseline,
           isolate->AdjustAmountOfExternalAllocatedMemory(-kTriggerGCSize));
}


TEST(Regress51719) {
  i::v8_flags.incremental_marking = false;
  CcTest::InitializeVM();

  const int64_t kTriggerGCSize =
      CcTest::i_isolate()->heap()->external_memory_hard_limit() + 1;
  v8::Isolate* isolate = CcTest::isolate();
  isolate->AdjustAmountOfExternalAllocatedMemory(kTriggerGCSize);
}

// Regression test for issue 54, object templates with embedder fields
// but no accessors or interceptors did not get their embedder field
// count set on instances.
THREADED_TEST(Regress54) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope outer(isolate);
  static v8::Persistent<v8::ObjectTemplate> templ;
  if (templ.IsEmpty()) {
    v8::EscapableHandleScope inner(isolate);
    v8::Local<v8::ObjectTemplate> local = v8::ObjectTemplate::New(isolate);
    local->SetInternalFieldCount(1);
    templ.Reset(isolate, inner.Escape(local));
  }
  v8::Local<v8::Object> result =
      v8::Local<v8::ObjectTemplate>::New(isolate, templ)
          ->NewInstance(context.local())
          .ToLocalChecked();
  CHECK_EQ(1, result->InternalFieldCount());
}


// If part of the threaded tests, this test makes ThreadingTest fail
// on mac.
TEST(CatchStackOverflow) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::TryCatch try_catch(context->GetIsolate());
  v8::Local<v8::Value> result = CompileRun(
      "function f() {"
      "  return f();"
      "}"
      ""
      "f();");
  CHECK(result.IsEmpty());
}


static void CheckTryCatchSourceInfo(v8::Local<v8::Script> script,
                                    const char* resource_name,
                                    int line_offset) {
  v8::HandleScope scope(CcTest::isolate());
  v8::TryCatch try_catch(CcTest::isolate());
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK(script->Run(context).IsEmpty());
  CHECK(try_catch.HasCaught());
  v8::Local<v8::Message> message = try_catch.Message();
  CHECK(!message.IsEmpty());
  CHECK_EQ(10 + line_offset, message->GetLineNumber(context).FromJust());
  CHECK_EQ(91, message->GetStartPosition());
  CHECK_EQ(92, message->GetEndPosition());
  CHECK_EQ(2, message->GetStartColumn(context).FromJust());
  CHECK_EQ(3, message->GetEndColumn(context).FromJust());
  v8::String::Utf8Value line(CcTest::isolate(),
                             message->GetSourceLine(context).ToLocalChecked());
  CHECK_EQ(0, strcmp("  throw 'nirk';", *line));
  v8::String::Utf8Value name(CcTest::isolate(),
                             message->GetScriptOrigin().ResourceName());
  CHECK_EQ(0, strcmp(resource_name, *name));
}


THREADED_TEST(TryCatchSourceInfo) {
  LocalContext context;
  v8::Isolate* isolate
```