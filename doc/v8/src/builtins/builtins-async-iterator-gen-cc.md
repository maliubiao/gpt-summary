Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Understand the Goal:** The request asks for the functionality of the provided C++ code, specifically focusing on its role within V8, potential connection to JavaScript, possible user errors, and whether it's a Torque file.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for recognizable terms. "AsyncFromSyncIterator," "Promise," "next," "return," "throw," "Iterator," "Builtin,"  "JSFunction," and "Context" jump out. These immediately suggest this code deals with asynchronous iteration, likely converting synchronous iterators to asynchronous ones. The presence of "Promise" further reinforces the asynchronous nature.

3. **Identify the Core Class:** The class `AsyncFromSyncBuiltinsAssembler` is central. Its methods like `Generate_AsyncFromSyncIteratorMethod`, `LoadIteratorResult`, and `CreateAsyncFromSyncIteratorCloseSyncAndRethrowClosure` seem to be the building blocks of the functionality.

4. **Analyze `Generate_AsyncFromSyncIteratorMethod`:** This function appears to be the workhorse. It takes an iterator, a sent value, a way to get the relevant method (`get_method`), and handles cases where the method is undefined. Key steps involve:
    * Creating a Promise.
    * Getting the relevant method (next, return, throw) from the synchronous iterator.
    * Calling the synchronous iterator's method.
    * Processing the result (value and done).
    * Resolving or rejecting the Promise based on the synchronous result.
    * Handling potential exceptions during the process, including closing the synchronous iterator if needed.

5. **Examine the Built-in Functions:**  The `TF_BUILTIN` macros (`AsyncFromSyncIteratorPrototypeNext`, `AsyncFromSyncIteratorPrototypeReturn`, `AsyncFromSyncIteratorPrototypeThrow`) clearly correspond to the methods of the `%AsyncFromSyncIteratorPrototype%` in JavaScript. This confirms the connection to JavaScript's async iteration.

6. **Understand `LoadIteratorResult`:**  This function is crucial for getting the `value` and `done` properties from the synchronous iterator's result. It handles both fast-path (optimized) and slow-path scenarios and explicitly checks for `TypeError` if the result isn't an object.

7. **Investigate the Closure:** `CreateAsyncFromSyncIteratorCloseSyncAndRethrowClosure` and `AllocateAsyncFromSyncIteratorCloseSyncAndRethrowContext` are about creating a closure to handle closing the synchronous iterator when an error occurs. This is a common pattern for resource management in asynchronous operations.

8. **Connect to JavaScript (and Provide Examples):** Now, having understood the C++ code, it's time to link it to JavaScript. The names of the built-in functions directly map to the methods on the async iterator prototype. The example provided in the request is a good starting point. Explain how the C++ code implements the behavior observed in the JavaScript.

9. **Identify Potential User Errors:** Think about how users might interact with async iterators and what could go wrong. Not implementing `return` or `throw` on the underlying synchronous iterator is a likely issue. Also, synchronous iterators throwing errors are handled by this code.

10. **Determine if it's Torque:** The prompt explicitly provides a hint: if the file ends in `.tq`, it's Torque. Since it ends in `.cc`, it's C++.

11. **Code Logic and Assumptions:** For the "code logic reasoning," focus on a specific scenario, like calling `next()`. Trace the execution path within `Generate_AsyncFromSyncIteratorMethod` and `LoadIteratorResult` with a simple input example. Clearly state the assumptions made.

12. **Structure the Response:**  Organize the findings into the categories requested: functionality, connection to JavaScript (with examples), code logic, and common errors. This makes the answer clear and easy to understand.

13. **Refine and Clarify:** Review the answer for clarity and accuracy. Ensure the JavaScript examples accurately illustrate the C++ code's behavior. Make sure the assumptions in the code logic section are explicit.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is about creating async iterators from scratch.
* **Correction:** The name "AsyncFromSyncIterator" and the focus on converting existing synchronous iterators make the primary purpose clearer.
* **Initial thought:**  The closure part might be overly complex to explain.
* **Refinement:** Focus on the purpose of the closure (closing the synchronous iterator on error) rather than getting bogged down in the implementation details of context allocation.
* **Initial thought:** The code logic section could be very detailed.
* **Refinement:** Keep the code logic example simple and focused on the core interactions. Avoid unnecessary complexity.

By following this structured analysis, combining code reading with domain knowledge of JavaScript and asynchronous programming, and iteratively refining the understanding, we can arrive at a comprehensive and accurate explanation of the provided V8 source code.
`v8/src/builtins/builtins-async-iterator-gen.cc` 是 V8 引擎中用于实现异步迭代器相关内置函数的 C++ 源代码文件。从文件名和代码内容来看，它负责处理将同步迭代器转换为异步迭代器的逻辑。

**功能列举:**

1. **实现 `%AsyncFromSyncIteratorPrototype%.next`:**  该内置函数用于异步地调用底层同步迭代器的 `next()` 方法，并将结果包装成 Promise。
2. **实现 `%AsyncFromSyncIteratorPrototype%.return`:** 该内置函数用于异步地调用底层同步迭代器的 `return()` 方法（如果存在），并将结果包装成 Promise。如果底层同步迭代器没有 `return()` 方法，它会创建一个已完成的迭代器结果对象 `{ value: value, done: true }` 并将其解析为 Promise。
3. **实现 `%AsyncFromSyncIteratorPrototype%.throw`:** 该内置函数用于异步地调用底层同步迭代器的 `throw()` 方法（如果存在），并将结果包装成 Promise。如果底层同步迭代器没有 `throw()` 方法，它会尝试关闭迭代器，然后用一个 `TypeError` 拒绝 Promise。
4. **实现 `AsyncFromSyncIteratorCloseSyncAndRethrow`:**  这是一个辅助函数，用于在异步操作中关闭底层的同步迭代器，并在出现错误时重新抛出异常。这通常用于 `throw()` 方法的错误处理中。
5. **提供一个通用的 `Generate_AsyncFromSyncIteratorMethod` 模板函数:**  这个函数封装了异步调用同步迭代器方法的通用逻辑，减少了 `next`、`return` 和 `throw` 方法实现的重复代码。它处理了获取同步迭代器方法、调用方法、处理结果（包括 `value` 和 `done` 属性）、以及 Promise 的 resolve 和 reject 等步骤。
6. **提供 `LoadIteratorResult` 函数:**  用于从同步迭代器的结果对象中提取 `value` 和 `done` 属性，并确保 `done` 属性被转换为布尔值。它还处理了结果对象不是对象的情况，抛出 `TypeError`。
7. **处理同步迭代器方法未定义的情况:** 对于 `return` 和 `throw` 方法，当底层同步迭代器没有这些方法时，代码会采取相应的处理措施，例如创建已完成的迭代器结果或抛出 `TypeError`。

**关于是否是 Torque 源代码:**

该文件以 `.cc` 结尾，表明它是一个 **C++ 源代码文件**。如果文件以 `.tq` 结尾，那么它才是 V8 的 Torque 源代码。Torque 是一种用于生成 V8 内置函数的领域特定语言。

**与 JavaScript 功能的关系及示例:**

`v8/src/builtins/builtins-async-iterator-gen.cc` 中实现的内置函数直接对应于 JavaScript 中异步迭代器原型对象上的方法。当我们在 JavaScript 中使用将同步迭代器转换为异步迭代器的功能时，V8 引擎会调用这里定义的 C++ 代码。

**JavaScript 示例:**

```javascript
async function* asyncFromSync(iterable) {
  for (const item of iterable) {
    yield item;
  }
}

const syncIterable = [1, 2, 3];
const asyncIterator = asyncFromSync(syncIterable)[Symbol.asyncIterator]();

async function testAsyncIterator() {
  console.log(await asyncIterator.next()); // { value: 1, done: false }
  console.log(await asyncIterator.next()); // { value: 2, done: false }
  console.log(await asyncIterator.next()); // { value: 3, done: false }
  console.log(await asyncIterator.next()); // { value: undefined, done: true }

  // Testing return
  const asyncIterator2 = asyncFromSync(syncIterable)[Symbol.asyncIterator]();
  console.log(await asyncIterator2.return(42)); // { value: 42, done: true }

  // Testing throw (requires a sync iterator with throw)
  // This example uses a custom sync iterator for demonstration
  const syncIterableWithThrow = {
    [Symbol.iterator]() {
      let i = 0;
      return {
        next() {
          if (i++ >= 2) {
            throw new Error("Sync Iterator Error");
          }
          return { value: i, done: false };
        },
        throw(err) {
          console.log("Sync iterator throw called:", err);
          return { value: undefined, done: true };
        },
      };
    },
    [Symbol.asyncIterator]() {
      return this[Symbol.iterator](); // Simplified for example
    }
  };

  const asyncIterator3 = asyncFromSync(syncIterableWithThrow)[Symbol.asyncIterator]();
  await asyncIterator3.next();
  await asyncIterator3.next();
  try {
    await asyncIterator3.next(); // This will trigger the sync iterator's throw
  } catch (e) {
    console.error("Async iterator caught:", e); // Error: Sync Iterator Error
  }
}

testAsyncIterator();
```

在这个例子中，`asyncFromSync` 函数创建了一个异步生成器，它实际上使用了 V8 引擎内部的异步迭代器机制。当我们调用 `asyncIterator.next()`、`asyncIterator.return()` 或 `asyncIterator.throw()` 时，最终会调用 `builtins-async-iterator-gen.cc` 中实现的相应 C++ 代码。

**代码逻辑推理 (假设 `AsyncFromSyncIteratorPrototypeNext`):**

**假设输入:**

* `iterator`: 一个指向 `JSAsyncFromSyncIterator` 对象的指针，它包装了一个同步迭代器 `[1, 2, 3]`。
* `value`:  `undefined` (因为 `next()` 方法通常不带参数)。
* `context`: 当前的 JavaScript 执行上下文。

**输出:**

一个 Promise，该 Promise 将解析为一个包含同步迭代器 `next()` 方法返回结果的对象，例如 `{ value: 1, done: false }`。

**详细逻辑:**

1. `AsyncFromSyncIteratorPrototypeNext` 函数被调用。
2. `Generate_AsyncFromSyncIteratorMethod` 函数被调用，传入相应的参数。
3. 从 `iterator` 对象中加载包装的同步迭代器。
4. 获取同步迭代器的 `next` 方法。
5. 调用同步迭代器的 `next()` 方法。
6. 使用 `LoadIteratorResult` 从返回结果中提取 `value` 和 `done`。
7. 创建一个新的 Promise。
8. 将提取的 `value` 和 `done` 包装成一个迭代器结果对象。
9. 使用该迭代器结果对象解析 Promise。
10. 返回该 Promise。

**如果同步迭代器的 `next()` 方法抛出异常:**

1. 在 `Generate_AsyncFromSyncIteratorMethod` 中，调用同步迭代器 `next()` 方法的代码块会使用 `ScopedExceptionHandler` 包裹。
2. 如果抛出异常，控制流会跳转到 `maybe_close_sync_then_reject_promise` 标签。
3. 如果 `close_on_rejection` 为真（`next` 方法是这种情况），会尝试关闭同步迭代器。
4. 使用捕获的异常拒绝 Promise。

**用户常见的编程错误:**

1. **假设同步迭代器的方法是异步的:** 用户可能会错误地认为底层的同步迭代器的 `next`、`return` 或 `throw` 方法本身是异步的并返回 Promise。实际上，`AsyncFromSyncIterator` 负责将同步操作转换为异步的。
   ```javascript
   // 错误示例 (假设 syncIterator.next 返回 Promise)
   const syncIterator = {
     [Symbol.iterator]() {
       return this;
     },
     next() {
       return Promise.resolve({ value: 1, done: false }); // 错误的假设
     }
   };
   const asyncIterator = asyncFromSync(syncIterator)[Symbol.asyncIterator]();
   // 这里的行为可能不是用户期望的，因为 AsyncFromSyncIterator 会直接调用同步的 Promise.resolve
   ```

2. **底层同步迭代器没有 `return` 或 `throw` 方法:** 当异步迭代器的 `return()` 或 `throw()` 方法被调用时，如果底层的同步迭代器没有相应的实现，行为会有所不同：
   * **`return()` 未定义:**  `AsyncFromSyncIterator` 会创建一个 `{ value: value, done: true }` 的迭代器结果并 resolve Promise。
   * **`throw()` 未定义:** `AsyncFromSyncIterator` 会尝试关闭迭代器，然后用一个 `TypeError` 拒绝 Promise，指示协议违规。

   ```javascript
   const syncIterableWithoutReturn = {
     [Symbol.iterator]() {
       let i = 0;
       return {
         next() { return i++ < 3 ? { value: i, done: false } : { value: undefined, done: true }; }
       };
     }
   };
   const asyncIteratorWithoutReturn = asyncFromSync(syncIterableWithoutReturn)[Symbol.asyncIterator]();
   console.log(await asyncIteratorWithoutReturn.return(42)); // 输出: { value: 42, done: true }

   const syncIterableWithoutThrow = {
     [Symbol.iterator]() {
       let i = 0;
       return {
         next() { return i++ < 3 ? { value: i, done: false } : { value: undefined, done: true }; }
       };
     }
   };
   const asyncIteratorWithoutThrow = asyncFromSync(syncIterableWithoutThrow)[Symbol.asyncIterator]();
   try {
     await asyncIteratorWithoutThrow.throw(new Error("Async Throw"));
   } catch (e) {
     console.error(e); // 输出 TypeError: syncIterator.throw is not a function
   }
   ```

理解 `builtins-async-iterator-gen.cc` 的功能有助于深入理解 JavaScript 异步迭代器的工作原理以及 V8 引擎是如何实现这些特性的。它展示了 V8 如何将高级的 JavaScript 概念映射到高效的底层 C++ 代码。

Prompt: 
```
这是目录为v8/src/builtins/builtins-async-iterator-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-async-iterator-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/builtins/builtins-async-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/execution/frames-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

namespace {
class AsyncFromSyncBuiltinsAssembler : public AsyncBuiltinsAssembler {
 public:
  // The 'next' and 'return' take an optional value parameter, and the 'throw'
  // method take an optional reason parameter.
  static const int kValueOrReasonArg = 0;

  explicit AsyncFromSyncBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : AsyncBuiltinsAssembler(state) {}

  using UndefinedMethodHandler = std::function<void(
      const TNode<NativeContext> native_context, const TNode<JSPromise> promise,
      const TNode<JSReceiver> sync_iterator, Label* if_exception)>;
  using SyncIteratorNodeGenerator =
      std::function<TNode<Object>(TNode<JSReceiver>)>;
  enum CloseOnRejectionOption { kDoNotCloseOnRejection, kCloseOnRejection };
  void Generate_AsyncFromSyncIteratorMethod(
      CodeStubArguments* args, const TNode<Context> context,
      const TNode<Object> iterator, const TNode<Object> sent_value,
      const SyncIteratorNodeGenerator& get_method,
      const UndefinedMethodHandler& if_method_undefined,
      const char* operation_name, CloseOnRejectionOption close_on_rejection,
      Label::Type reject_label_type = Label::kDeferred,
      std::optional<TNode<Object>> initial_exception_value = std::nullopt);

  void Generate_AsyncFromSyncIteratorMethod(
      CodeStubArguments* args, const TNode<Context> context,
      const TNode<Object> iterator, const TNode<Object> sent_value,
      Handle<String> name, const UndefinedMethodHandler& if_method_undefined,
      const char* operation_name, CloseOnRejectionOption close_on_rejection,
      Label::Type reject_label_type = Label::kDeferred,
      std::optional<TNode<Object>> initial_exception_value = std::nullopt) {
    auto get_method = [=, this](const TNode<JSReceiver> sync_iterator) {
      return GetProperty(context, sync_iterator, name);
    };
    return Generate_AsyncFromSyncIteratorMethod(
        args, context, iterator, sent_value, get_method, if_method_undefined,
        operation_name, close_on_rejection, reject_label_type,
        initial_exception_value);
  }

  // Load "value" and "done" from an iterator result object. If an exception
  // is thrown at any point, jumps to the `if_exception` label with exception
  // stored in `var_exception`.
  //
  // Returns a Pair of Nodes, whose first element is the value of the "value"
  // property, and whose second element is the value of the "done" property,
  // converted to a Boolean if needed.
  std::pair<TNode<Object>, TNode<Boolean>> LoadIteratorResult(
      const TNode<Context> context, const TNode<NativeContext> native_context,
      const TNode<Object> iter_result, Label* if_exception,
      TVariable<Object>* var_exception);

  // Synthetic Context for the AsyncFromSyncIterator rejection closure that
  // closes the underlying sync iterator.
  struct AsyncFromSyncIteratorCloseSyncAndRethrowContext {
    enum Fields { kSyncIterator = Context::MIN_CONTEXT_SLOTS, kLength };
  };

  TNode<JSFunction> CreateAsyncFromSyncIteratorCloseSyncAndRethrowClosure(
      TNode<NativeContext> native_context, TNode<JSReceiver> sync_iterator);

  TNode<Context> AllocateAsyncFromSyncIteratorCloseSyncAndRethrowContext(
      TNode<NativeContext> native_context, TNode<JSReceiver> sync_iterator);
};

// This implements common steps found in various AsyncFromSyncIterator prototype
// methods followed by ES#sec-asyncfromsynciteratorcontinuation. The differences
// between the various prototype methods are handled by the get_method and
// if_method_undefined callbacks.
void AsyncFromSyncBuiltinsAssembler::Generate_AsyncFromSyncIteratorMethod(
    CodeStubArguments* args, const TNode<Context> context,
    const TNode<Object> iterator, const TNode<Object> sent_value,
    const SyncIteratorNodeGenerator& get_method,
    const UndefinedMethodHandler& if_method_undefined,
    const char* operation_name, CloseOnRejectionOption close_on_rejection,
    Label::Type reject_label_type,
    std::optional<TNode<Object>> initial_exception_value) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<JSPromise> promise = NewJSPromise(context);

  TVARIABLE(
      Object, var_exception,
      initial_exception_value ? *initial_exception_value : UndefinedConstant());
  Label maybe_close_sync_then_reject_promise(this, reject_label_type);
  Label maybe_close_sync_if_not_done_then_reject_promise(this,
                                                         reject_label_type);

  // At this time %AsyncFromSyncIterator% does not escape to user code, and so
  // cannot be called with an incompatible receiver.
  CSA_CHECK(this,
            HasInstanceType(CAST(iterator), JS_ASYNC_FROM_SYNC_ITERATOR_TYPE));
  TNode<JSAsyncFromSyncIterator> async_iterator = CAST(iterator);
  const TNode<JSReceiver> sync_iterator = LoadObjectField<JSReceiver>(
      async_iterator, JSAsyncFromSyncIterator::kSyncIteratorOffset);

  TNode<Object> method = get_method(sync_iterator);

  if (if_method_undefined) {
    Label if_isnotundefined(this);

    GotoIfNot(IsNullOrUndefined(method), &if_isnotundefined);
    if_method_undefined(native_context, promise, sync_iterator,
                        &maybe_close_sync_then_reject_promise);

    BIND(&if_isnotundefined);
  }

  TVARIABLE(Object, iter_result);
  {
    Label has_sent_value(this), no_sent_value(this), merge(this);
    ScopedExceptionHandler handler(this, &maybe_close_sync_then_reject_promise,
                                   &var_exception);
    Branch(IntPtrGreaterThan(args->GetLengthWithoutReceiver(),
                             IntPtrConstant(kValueOrReasonArg)),
           &has_sent_value, &no_sent_value);
    BIND(&has_sent_value);
    {
      iter_result = Call(context, method, sync_iterator, sent_value);
      Goto(&merge);
    }
    BIND(&no_sent_value);
    {
      iter_result = Call(context, method, sync_iterator);
      Goto(&merge);
    }
    BIND(&merge);
  }

  TNode<Object> value;
  TNode<Boolean> done;
  std::tie(value, done) =
      LoadIteratorResult(context, native_context, iter_result.value(),
                         &maybe_close_sync_then_reject_promise, &var_exception);

  const TNode<JSFunction> promise_fun =
      CAST(LoadContextElement(native_context, Context::PROMISE_FUNCTION_INDEX));
  CSA_DCHECK(this, IsConstructor(promise_fun));

  // 6. Let valueWrapper be PromiseResolve(%Promise%, « value »).
  //    IfAbruptRejectPromise(valueWrapper, promiseCapability).
  TNode<Object> value_wrapper;
  {
    ScopedExceptionHandler handler(
        this, &maybe_close_sync_if_not_done_then_reject_promise,
        &var_exception);
    value_wrapper = CallBuiltin(Builtin::kPromiseResolve, native_context,
                                promise_fun, value);
  }

  // 10. Let onFulfilled be CreateBuiltinFunction(unwrap, 1, "", « »).
  const TNode<JSFunction> on_fulfilled =
      CreateUnwrapClosure(native_context, done);

  // 12. If done is true, or if closeOnRejection is false, then
  //   a. Let onRejected be undefined.
  // 13. Else,
  //   [...]
  //   b. Let onRejected be CreateBuiltinFunction(closeIterator, 1, "", « »).
  TNode<Object> on_rejected;
  if (close_on_rejection == kCloseOnRejection) {
    on_rejected = Select<Object>(
        IsTrue(done), [=, this] { return UndefinedConstant(); },
        [=, this] {
          return CreateAsyncFromSyncIteratorCloseSyncAndRethrowClosure(
              native_context, sync_iterator);
        });
  } else {
    on_rejected = UndefinedConstant();
  }

  // 14. Perform ! PerformPromiseThen(valueWrapper,
  //     onFulfilled, onRejected, promiseCapability).
  args->PopAndReturn(CallBuiltin(Builtin::kPerformPromiseThen, context,
                                 value_wrapper, on_fulfilled, on_rejected,
                                 promise));

  Label reject_promise(this);
  BIND(&maybe_close_sync_if_not_done_then_reject_promise);
  {
    if (close_on_rejection == kCloseOnRejection) {
      GotoIf(IsFalse(done), &maybe_close_sync_then_reject_promise);
    }
    Goto(&reject_promise);
  }
  BIND(&maybe_close_sync_then_reject_promise);
  {
    if (close_on_rejection == kCloseOnRejection) {
      // 7. If valueWrapper is an abrupt completion, done is false, and
      //    closeOnRejection is true, then
      //   a. Set valueWrapper to Completion(IteratorClose(syncIteratorRecord,
      //      valueWrapper)).
      TorqueStructIteratorRecord sync_iterator_record = {sync_iterator, {}};
      IteratorCloseOnException(context, sync_iterator_record);
    }
    Goto(&reject_promise);
  }
  BIND(&reject_promise);
  {
    const TNode<Object> exception = var_exception.value();
    CallBuiltin(Builtin::kRejectPromise, context, promise, exception,
                TrueConstant());
    args->PopAndReturn(promise);
  }
}

std::pair<TNode<Object>, TNode<Boolean>>
AsyncFromSyncBuiltinsAssembler::LoadIteratorResult(
    const TNode<Context> context, const TNode<NativeContext> native_context,
    const TNode<Object> iter_result, Label* if_exception,
    TVariable<Object>* var_exception) {
  Label if_fastpath(this), if_slowpath(this), merge(this), to_boolean(this),
      done(this), if_notanobject(this, Label::kDeferred);
  GotoIf(TaggedIsSmi(iter_result), &if_notanobject);

  const TNode<Map> iter_result_map = LoadMap(CAST(iter_result));
  GotoIfNot(JSAnyIsNotPrimitiveMap(iter_result_map), &if_notanobject);

  const TNode<Object> fast_iter_result_map =
      LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX);

  TVARIABLE(Object, var_value);
  TVARIABLE(Object, var_done);
  Branch(TaggedEqual(iter_result_map, fast_iter_result_map), &if_fastpath,
         &if_slowpath);

  BIND(&if_fastpath);
  {
    TNode<JSObject> fast_iter_result = CAST(iter_result);
    var_done = LoadObjectField(fast_iter_result, JSIteratorResult::kDoneOffset);
    var_value =
        LoadObjectField(fast_iter_result, JSIteratorResult::kValueOffset);
    Goto(&merge);
  }

  BIND(&if_slowpath);
  {
    ScopedExceptionHandler handler(this, if_exception, var_exception);

    // Let nextDone be IteratorComplete(nextResult).
    // IfAbruptRejectPromise(nextDone, promiseCapability).
    const TNode<Object> iter_result_done =
        GetProperty(context, iter_result, factory()->done_string());

    // Let nextValue be IteratorValue(nextResult).
    // IfAbruptRejectPromise(nextValue, promiseCapability).
    const TNode<Object> iter_result_value =
        GetProperty(context, iter_result, factory()->value_string());

    var_value = iter_result_value;
    var_done = iter_result_done;
    Goto(&merge);
  }

  BIND(&if_notanobject);
  {
    // Sync iterator result is not an object --- Produce a TypeError and jump
    // to the `if_exception` path.
    const TNode<Object> error = MakeTypeError(
        MessageTemplate::kIteratorResultNotAnObject, context, iter_result);
    *var_exception = error;
    Goto(if_exception);
  }

  BIND(&merge);
  // Ensure `iterResult.done` is a Boolean.
  GotoIf(TaggedIsSmi(var_done.value()), &to_boolean);
  Branch(IsBoolean(CAST(var_done.value())), &done, &to_boolean);

  BIND(&to_boolean);
  {
    const TNode<Object> result =
        CallBuiltin(Builtin::kToBoolean, context, var_done.value());
    var_done = result;
    Goto(&done);
  }

  BIND(&done);
  return std::make_pair(var_value.value(), CAST(var_done.value()));
}

TNode<JSFunction> AsyncFromSyncBuiltinsAssembler::
    CreateAsyncFromSyncIteratorCloseSyncAndRethrowClosure(
        TNode<NativeContext> native_context, TNode<JSReceiver> sync_iterator) {
  const TNode<Context> closure_context =
      AllocateAsyncFromSyncIteratorCloseSyncAndRethrowContext(native_context,
                                                              sync_iterator);
  return AllocateRootFunctionWithContext(
      RootIndex::kAsyncFromSyncIteratorCloseSyncAndRethrowSharedFun,
      closure_context, native_context);
}

TNode<Context> AsyncFromSyncBuiltinsAssembler::
    AllocateAsyncFromSyncIteratorCloseSyncAndRethrowContext(
        TNode<NativeContext> native_context, TNode<JSReceiver> sync_iterator) {
  TNode<Context> context = AllocateSyntheticFunctionContext(
      native_context, AsyncFromSyncIteratorCloseSyncAndRethrowContext::kLength);
  StoreContextElementNoWriteBarrier(
      context, AsyncFromSyncIteratorCloseSyncAndRethrowContext::kSyncIterator,
      sync_iterator);
  return context;
}

}  // namespace

// ES#sec-%asyncfromsynciteratorprototype%.next
TF_BUILTIN(AsyncFromSyncIteratorPrototypeNext, AsyncFromSyncBuiltinsAssembler) {
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  const TNode<Object> iterator = args.GetReceiver();
  const TNode<Object> value = args.GetOptionalArgumentValue(kValueOrReasonArg);
  const auto context = Parameter<Context>(Descriptor::kContext);

  auto get_method = [=, this](const TNode<JSReceiver> unused) {
    return LoadObjectField(CAST(iterator),
                           JSAsyncFromSyncIterator::kNextOffset);
  };
  Generate_AsyncFromSyncIteratorMethod(
      &args, context, iterator, value, get_method, UndefinedMethodHandler(),
      "[Async-from-Sync Iterator].prototype.next", kCloseOnRejection);
}

// ES#sec-%asyncfromsynciteratorprototype%.return
TF_BUILTIN(AsyncFromSyncIteratorPrototypeReturn,
           AsyncFromSyncBuiltinsAssembler) {
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  const TNode<Object> iterator = args.GetReceiver();
  const TNode<Object> value = args.GetOptionalArgumentValue(kValueOrReasonArg);
  const auto context = Parameter<Context>(Descriptor::kContext);

  auto if_return_undefined = [=, this, &args](
                                 const TNode<NativeContext> native_context,
                                 const TNode<JSPromise> promise,
                                 const TNode<JSReceiver> sync_iterator,
                                 Label* if_exception) {
    // If return is undefined, then
    // Let iterResult be ! CreateIterResultObject(value, true)
    const TNode<Object> iter_result = CallBuiltin(
        Builtin::kCreateIterResultObject, context, value, TrueConstant());

    // Perform ! Call(promiseCapability.[[Resolve]], undefined, « iterResult »).
    // IfAbruptRejectPromise(nextDone, promiseCapability).
    // Return promiseCapability.[[Promise]].
    CallBuiltin(Builtin::kResolvePromise, context, promise, iter_result);
    args.PopAndReturn(promise);
  };

  Generate_AsyncFromSyncIteratorMethod(
      &args, context, iterator, value, factory()->return_string(),
      if_return_undefined, "[Async-from-Sync Iterator].prototype.return",
      kDoNotCloseOnRejection);
}

// ES#sec-%asyncfromsynciteratorprototype%.throw
TF_BUILTIN(AsyncFromSyncIteratorPrototypeThrow,
           AsyncFromSyncBuiltinsAssembler) {
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  const TNode<Object> iterator = args.GetReceiver();
  const TNode<Object> reason = args.GetOptionalArgumentValue(kValueOrReasonArg);
  const auto context = Parameter<Context>(Descriptor::kContext);

  // 8. If throw is undefined, then
  auto if_throw_undefined =
      [=, this, &args](const TNode<NativeContext> native_context,
                       const TNode<JSPromise> promise,
                       const TNode<JSReceiver> sync_iterator,
                       Label* if_exception) {
        // a. NOTE: If syncIterator does not have a `throw` method, close it to
        //    give it a chance to clean up before we reject the capability.
        // b. Let closeCompletion be NormalCompletion(~empty~).
        // c. Let result be Completion(IteratorClose(syncIteratorRecord,
        //    closeCompletion)).
        TVARIABLE(Object, var_reject_value);
        Label done(this);
        {
          ScopedExceptionHandler handler(this, &done, &var_reject_value);
          TorqueStructIteratorRecord sync_iterator_record = {sync_iterator, {}};
          IteratorClose(context, sync_iterator_record);

          // d. IfAbruptRejectPromise(result, promiseCapability).
          // (Done below)
        }

        // e. NOTE: The next step throws a *TypeError* to indicate that there
        //    was a protocol violation: syncIterator does not have a `throw`
        //    method.
        // f. NOTE: If closing syncIterator does not throw then the result of
        //    that operation is ignored, even if it yields a rejected promise.
        // g. Perform ! Call(promiseCapability.[[Reject]], *undefined*, « a
        //    newly created *TypeError* object »).
        var_reject_value =
            MakeTypeError(MessageTemplate::kThrowMethodMissing, context);
        Goto(&done);
        BIND(&done);
        CallBuiltin(Builtin::kRejectPromise, context, promise,
                    var_reject_value.value(), TrueConstant());
        args.PopAndReturn(promise);
      };

  Generate_AsyncFromSyncIteratorMethod(
      &args, context, iterator, reason, factory()->throw_string(),
      if_throw_undefined, "[Async-from-Sync Iterator].prototype.throw",
      kCloseOnRejection, Label::kNonDeferred, reason);
}

TF_BUILTIN(AsyncFromSyncIteratorCloseSyncAndRethrow,
           AsyncFromSyncBuiltinsAssembler) {
  // #sec-asyncfromsynciteratorcontinuation
  //
  // 13. [...]
  //   a. Let closeIterator be a new Abstract Closure with parameters (error)
  //      that captures syncIteratorRecord and performs the following steps
  //      when called:
  //        i. Return ? IteratorClose(syncIteratorRecord,
  //           ThrowCompletion(error)).

  auto error = Parameter<Object>(Descriptor::kError);
  auto context = Parameter<Context>(Descriptor::kContext);

  const TNode<JSReceiver> sync_iterator = CAST(LoadContextElement(
      context, AsyncFromSyncIteratorCloseSyncAndRethrowContext::kSyncIterator));
  // iterator.next field is not used by IteratorCloseOnException.
  TorqueStructIteratorRecord sync_iterator_record = {sync_iterator, {}};
  IteratorCloseOnException(context, sync_iterator_record);
  Return(CallRuntime(Runtime::kReThrow, context, error));
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""

```