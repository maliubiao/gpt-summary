Response: Let's break down the thought process to analyze the C++ code and explain its function and relation to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and its connection to JavaScript, including a JavaScript example. The file path `v8/src/builtins/builtins-async-generator-gen.cc` strongly suggests it's related to the implementation of asynchronous generators in V8 (the JavaScript engine).

2. **Initial Skim and Keywords:** Quickly scan the code for keywords and familiar terms. Keywords like `async`, `generator`, `Promise`, `await`, `next`, `return`, `throw`, `enqueue`, `resolve`, `reject`, and class names like `AsyncGeneratorBuiltinsAssembler` are significant. These immediately point towards the core concepts of asynchronous generators in JavaScript.

3. **Identify the Core Class:** The `AsyncGeneratorBuiltinsAssembler` class seems central. It inherits from `AsyncBuiltinsAssembler`, which likely handles common logic for asynchronous operations. The assembler suffix suggests this code is involved in generating machine code for these built-in functions.

4. **Analyze Helper Functions within the Class:**  Focus on the smaller, self-contained functions within `AsyncGeneratorBuiltinsAssembler`.

    * **State Management:** Functions like `LoadGeneratorState`, `IsGeneratorStateClosed`, `IsGeneratorClosed`, `IsGeneratorStateSuspended`, `IsGeneratorNotExecuting`, `IsGeneratorAwaiting`, `SetGeneratorAwaiting`, `SetGeneratorNotAwaiting`, and `CloseGenerator` clearly deal with tracking the internal state of an async generator object. This is crucial for managing the asynchronous execution flow.

    * **Request Queue Management:** Functions like `LoadFirstAsyncGeneratorRequestFromQueue`, `LoadResumeTypeFromAsyncGeneratorRequest`, `LoadPromiseFromAsyncGeneratorRequest`, `LoadValueFromAsyncGeneratorRequest`, `AddAsyncGeneratorRequestToQueue`, `TakeFirstAsyncGeneratorRequestFromQueue`, and `AllocateAsyncGeneratorRequest` indicate a queue is used to manage pending operations (`next`, `return`, `throw`) on the async generator. Each request seems to hold a promise and a value.

    * **Core Operations:** Functions like `AsyncGeneratorEnqueue`, `AsyncGeneratorAwait`, `AsyncGeneratorAwaitResume`, `AsyncGeneratorResolve`, `AsyncGeneratorReject`, `AsyncGeneratorReturnClosedReject` implement the fundamental logic of how async generators handle different stages of their execution and interactions with promises.

5. **Connect to JavaScript Concepts:**  As the helper functions are understood, start connecting them to the corresponding JavaScript features.

    * The state management functions directly relate to the internal states of an async generator as defined in the ECMAScript specification (e.g., "suspended", "closed", "executing").
    * The request queue corresponds to how JavaScript engines manage the order of `next()`, `return()`, and `throw()` calls on an async generator. Each call creates a promise that resolves or rejects based on the generator's state and the provided value.
    * `AsyncGeneratorEnqueue` is the underlying mechanism for calling `next()`, `return()`, and `throw()` on the async generator. It creates a promise and adds a request to the queue.
    * `AsyncGeneratorAwait` handles the suspension of the generator when an `await` expression is encountered.
    * `AsyncGeneratorResolve` and `AsyncGeneratorReject` are the internal mechanisms for fulfilling or rejecting the promises associated with the async generator's operations.

6. **Analyze the Built-in Functions (TF_BUILTIN):** The `TF_BUILTIN` macros define the actual built-in functions that JavaScript code can call. Match these to the prototype methods of `AsyncGenerator`:

    * `AsyncGeneratorPrototypeNext`: Implements the `.next()` method.
    * `AsyncGeneratorPrototypeReturn`: Implements the `.return()` method.
    * `AsyncGeneratorPrototypeThrow`: Implements the `.throw()` method.
    * `AsyncGeneratorAwaitResolveClosure`, `AsyncGeneratorAwaitRejectClosure`: These are callback functions used internally when a promise awaited within the generator resolves or rejects.
    * `AsyncGeneratorAwait`: The core logic for handling `await` within the generator.
    * `AsyncGeneratorResumeNext`:  The central loop that processes the request queue and drives the generator's execution.
    * `AsyncGeneratorResolve`, `AsyncGeneratorReject`:  Internal functions for resolving or rejecting the promises associated with generator operations.
    * `AsyncGeneratorYieldWithAwait`, `AsyncGeneratorYieldWithAwaitResolveClosure`: Handle the specific case of `yield await`.
    * `AsyncGeneratorReturn`, `AsyncGeneratorReturnResolveClosure`, `AsyncGeneratorReturnClosedResolveClosure`, `AsyncGeneratorReturnClosedRejectClosure`: Handle the specifics of the `.return()` method, including cases where the generator is already closed.

7. **Formulate the Summary:** Based on the analysis, write a concise summary of the file's purpose, highlighting its role in implementing the behavior of JavaScript's async generators. Emphasize the connection to the specification and the key operations involved.

8. **Create the JavaScript Example:**  Construct a simple JavaScript example that demonstrates the core functionalities implemented in the C++ code. Show the creation of an async generator, calling `next()`, `return()`, and `throw()`, and using `await`. This will make the connection between the C++ implementation and the JavaScript behavior concrete. Focus on illustrating the queueing mechanism and the handling of different completion types (normal, return, throw).

9. **Review and Refine:** Read through the summary and the JavaScript example to ensure accuracy, clarity, and completeness. Make sure the terminology is consistent and understandable. Check for any missed details or areas that could be explained more effectively. For example, initially, I might not have explicitly mentioned the "request queue," but upon closer inspection of the functions dealing with `AsyncGeneratorRequest`, its importance becomes clear and needs to be included in the summary. Similarly, highlighting that the C++ code is *implementing* the *specification* is crucial.
这个C++源代码文件 `builtins-async-generator-gen.cc` 是 V8 JavaScript 引擎的一部分，**主要负责实现 ECMAScript 规范中定义的异步生成器（Async Generator）相关的内置函数。**

简单来说，它包含了异步生成器原型对象上的方法（如 `next`, `return`, `throw`）以及内部操作（如 `AsyncGeneratorAwait`, `AsyncGeneratorResolve`, `AsyncGeneratorReject`）的具体 C++ 代码实现。

**它与 JavaScript 的功能有密切关系。**  异步生成器是 JavaScript 的一个重要特性，允许开发者编写看起来同步但实际上是非阻塞的异步代码。

**以下是该文件功能的归纳：**

1. **实现异步生成器原型方法：**
   - `AsyncGeneratorPrototypeNext`: 实现 `AsyncGenerator.prototype.next()` 方法，用于推动异步生成器执行并获取下一个值。
   - `AsyncGeneratorPrototypeReturn`: 实现 `AsyncGenerator.prototype.return()` 方法，用于提前结束异步生成器的执行并返回一个指定的值。
   - `AsyncGeneratorPrototypeThrow`: 实现 `AsyncGenerator.prototype.throw()` 方法，用于向异步生成器中抛出一个错误。

2. **管理异步生成器的状态和执行流程：**
   - 定义了用于检查和修改异步生成器状态的辅助函数，例如判断生成器是否已关闭、是否正在执行、是否正在等待等。
   - 实现了异步生成器请求队列的管理，用于存储待处理的 `next`, `return`, `throw` 操作。
   - 实现了 `AsyncGeneratorResumeNext` 函数，它是异步生成器执行的核心循环，负责从请求队列中取出请求并驱动生成器执行。

3. **处理 `await` 表达式：**
   - `AsyncGeneratorAwait`:  实现了 `await` 关键字在异步生成器中的行为，即暂停生成器的执行，等待 Promise 解决，然后根据 Promise 的结果恢复执行。
   - `AsyncGeneratorAwaitResolveClosure` 和 `AsyncGeneratorAwaitRejectClosure`:  是 `await` 等待的 Promise 解决或拒绝后执行的回调函数，用于恢复异步生成器的执行。

4. **处理异步生成器的完成 (Resolve) 和拒绝 (Reject)：**
   - `AsyncGeneratorResolve`: 实现异步生成器成功产生一个值时的处理逻辑，包括创建迭代器结果对象并解决相应的 Promise。
   - `AsyncGeneratorReject`: 实现异步生成器发生错误时的处理逻辑，包括拒绝相应的 Promise。

5. **处理 `yield await` 表达式：**
   - `AsyncGeneratorYieldWithAwait`: 实现了 `yield await` 表达式的行为，结合了 `yield` 和 `await` 的语义。

**JavaScript 示例说明：**

```javascript
async function* myAsyncGenerator() {
  console.log('开始执行');
  yield await Promise.resolve(1);
  console.log('第一次 yield 后');
  yield await Promise.resolve(2);
  console.log('第二次 yield 后');
  return 3;
}

async function main() {
  const generator = myAsyncGenerator();

  console.log('调用 next 第一次');
  const result1 = await generator.next();
  console.log('next 第一次结果:', result1); // { value: 1, done: false }

  console.log('调用 next 第二次');
  const result2 = await generator.next();
  console.log('next 第二次结果:', result2); // { value: 2, done: false }

  console.log('调用 return');
  const resultReturn = await generator.return(10);
  console.log('return 结果:', resultReturn); // { value: 10, done: true }

  console.log('调用 next 第三次 (实际上不会执行)');
  const result3 = await generator.next();
  console.log('next 第三次结果:', result3); // { value: undefined, done: true }

  // 演示 throw
  const generator2 = myAsyncGenerator();
  await generator2.next(); // 先执行到第一个 yield
  try {
    await generator2.throw(new Error('Something went wrong'));
  } catch (error) {
    console.error('捕获到错误:', error);
  }
  const result4 = await generator2.next();
  console.log('next 后的结果 (由于 throw 已经结束):', result4); // { value: undefined, done: true }
}

main();
```

**在这个例子中：**

- `async function* myAsyncGenerator()` 定义了一个异步生成器。
- `yield await Promise.resolve(1)` 和 `yield await Promise.resolve(2)` 演示了异步生成器如何暂停执行，等待 Promise 解决后再继续。这对应了 C++ 代码中的 `AsyncGeneratorAwait` 和相关的回调函数。
- `generator.next()` 调用对应了 C++ 代码中的 `AsyncGeneratorPrototypeNext`，它会将一个请求添加到异步生成器的请求队列中，并最终由 `AsyncGeneratorResumeNext` 来处理。
- `generator.return(10)` 调用对应了 C++ 代码中的 `AsyncGeneratorPrototypeReturn`，用于提前结束生成器并返回指定的值。
- `generator.throw(new Error('Something went wrong'))` 调用对应了 C++ 代码中的 `AsyncGeneratorPrototypeThrow`，用于向生成器抛出错误。

总而言之，`builtins-async-generator-gen.cc` 文件是 V8 引擎实现异步生成器这一重要 JavaScript 特性的核心组成部分，它将 ECMAScript 规范中定义的异步生成器的行为转化为可执行的 C++ 代码，使得 JavaScript 开发者能够使用异步生成器编写更清晰、易于理解的异步代码。

Prompt: 
```
这是目录为v8/src/builtins/builtins-async-generator-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-async-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/execution/frames-inl.h"
#include "src/objects/js-generator.h"
#include "src/objects/js-promise.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

namespace {

class AsyncGeneratorBuiltinsAssembler : public AsyncBuiltinsAssembler {
 public:
  explicit AsyncGeneratorBuiltinsAssembler(CodeAssemblerState* state)
      : AsyncBuiltinsAssembler(state) {}

  inline TNode<Smi> LoadGeneratorState(
      const TNode<JSGeneratorObject> generator) {
    return LoadObjectField<Smi>(generator,
                                JSGeneratorObject::kContinuationOffset);
  }

  inline TNode<BoolT> IsGeneratorStateClosed(const TNode<Smi> state) {
    return SmiEqual(state, SmiConstant(JSGeneratorObject::kGeneratorClosed));
  }
  inline TNode<BoolT> IsGeneratorClosed(
      const TNode<JSGeneratorObject> generator) {
    return IsGeneratorStateClosed(LoadGeneratorState(generator));
  }

  inline TNode<BoolT> IsGeneratorStateSuspended(const TNode<Smi> state) {
    return SmiGreaterThanOrEqual(state, SmiConstant(0));
  }

  inline TNode<BoolT> IsGeneratorSuspended(
      const TNode<JSGeneratorObject> generator) {
    return IsGeneratorStateSuspended(LoadGeneratorState(generator));
  }

  inline TNode<BoolT> IsGeneratorStateSuspendedAtStart(const TNode<Smi> state) {
    return SmiEqual(state, SmiConstant(0));
  }

  inline TNode<BoolT> IsGeneratorStateNotExecuting(const TNode<Smi> state) {
    return SmiNotEqual(state,
                       SmiConstant(JSGeneratorObject::kGeneratorExecuting));
  }
  inline TNode<BoolT> IsGeneratorNotExecuting(
      const TNode<JSGeneratorObject> generator) {
    return IsGeneratorStateNotExecuting(LoadGeneratorState(generator));
  }

  inline TNode<BoolT> IsGeneratorAwaiting(
      const TNode<JSGeneratorObject> generator) {
    TNode<Object> is_generator_awaiting =
        LoadObjectField(generator, JSAsyncGeneratorObject::kIsAwaitingOffset);
    return TaggedEqual(is_generator_awaiting, SmiConstant(1));
  }

  inline void SetGeneratorAwaiting(const TNode<JSGeneratorObject> generator) {
    CSA_DCHECK(this, Word32BinaryNot(IsGeneratorAwaiting(generator)));
    StoreObjectFieldNoWriteBarrier(
        generator, JSAsyncGeneratorObject::kIsAwaitingOffset, SmiConstant(1));
    CSA_DCHECK(this, IsGeneratorAwaiting(generator));
  }

  inline void SetGeneratorNotAwaiting(
      const TNode<JSGeneratorObject> generator) {
    CSA_DCHECK(this, IsGeneratorAwaiting(generator));
    StoreObjectFieldNoWriteBarrier(
        generator, JSAsyncGeneratorObject::kIsAwaitingOffset, SmiConstant(0));
    CSA_DCHECK(this, Word32BinaryNot(IsGeneratorAwaiting(generator)));
  }

  inline void CloseGenerator(const TNode<JSGeneratorObject> generator) {
    StoreObjectFieldNoWriteBarrier(
        generator, JSGeneratorObject::kContinuationOffset,
        SmiConstant(JSGeneratorObject::kGeneratorClosed));
  }

  inline TNode<HeapObject> LoadFirstAsyncGeneratorRequestFromQueue(
      const TNode<JSGeneratorObject> generator) {
    return LoadObjectField<HeapObject>(generator,
                                       JSAsyncGeneratorObject::kQueueOffset);
  }

  inline TNode<Smi> LoadResumeTypeFromAsyncGeneratorRequest(
      const TNode<AsyncGeneratorRequest> request) {
    return LoadObjectField<Smi>(request,
                                AsyncGeneratorRequest::kResumeModeOffset);
  }

  inline TNode<JSPromise> LoadPromiseFromAsyncGeneratorRequest(
      const TNode<AsyncGeneratorRequest> request) {
    return LoadObjectField<JSPromise>(request,
                                      AsyncGeneratorRequest::kPromiseOffset);
  }

  inline TNode<Object> LoadValueFromAsyncGeneratorRequest(
      const TNode<AsyncGeneratorRequest> request) {
    return LoadObjectField(request, AsyncGeneratorRequest::kValueOffset);
  }

  inline TNode<BoolT> IsAbruptResumeType(const TNode<Smi> resume_type) {
    return SmiNotEqual(resume_type, SmiConstant(JSGeneratorObject::kNext));
  }

  void AsyncGeneratorEnqueue(CodeStubArguments* args, TNode<Context> context,
                             TNode<Object> receiver, TNode<Object> value,
                             JSAsyncGeneratorObject::ResumeMode resume_mode,
                             const char* method_name);

  TNode<AsyncGeneratorRequest> TakeFirstAsyncGeneratorRequestFromQueue(
      TNode<JSAsyncGeneratorObject> generator);
  void AddAsyncGeneratorRequestToQueue(TNode<JSAsyncGeneratorObject> generator,
                                       TNode<AsyncGeneratorRequest> request);

  TNode<AsyncGeneratorRequest> AllocateAsyncGeneratorRequest(
      JSAsyncGeneratorObject::ResumeMode resume_mode,
      TNode<Object> resume_value, TNode<JSPromise> promise);

  // Shared implementation of the catchable and uncatchable variations of Await
  // for AsyncGenerators.
  template <typename Descriptor>
  void AsyncGeneratorAwait();
  void AsyncGeneratorAwaitResume(
      TNode<Context> context,
      TNode<JSAsyncGeneratorObject> async_generator_object, TNode<Object> value,
      JSAsyncGeneratorObject::ResumeMode resume_mode);
  void AsyncGeneratorAwaitResumeClosure(
      TNode<Context> context, TNode<Object> value,
      JSAsyncGeneratorObject::ResumeMode resume_mode);
  void AsyncGeneratorReturnClosedReject(
      TNode<Context> context,
      TNode<JSAsyncGeneratorObject> async_generator_object,
      TNode<Object> value);
};

// Shared implementation for the 3 Async Iterator protocol methods of Async
// Generators.
void AsyncGeneratorBuiltinsAssembler::AsyncGeneratorEnqueue(
    CodeStubArguments* args, TNode<Context> context, TNode<Object> receiver,
    TNode<Object> value, JSAsyncGeneratorObject::ResumeMode resume_mode,
    const char* method_name) {
  // AsyncGeneratorEnqueue produces a new Promise, and appends it to the list
  // of async generator requests to be executed. If the generator is not
  // presently executing, then this method will loop through, processing each
  // request from front to back.
  // This loop resides in AsyncGeneratorResumeNext.
  TNode<JSPromise> promise = NewJSPromise(context);

  Label if_receiverisincompatible(this, Label::kDeferred);
  GotoIf(TaggedIsSmi(receiver), &if_receiverisincompatible);
  GotoIfNot(HasInstanceType(CAST(receiver), JS_ASYNC_GENERATOR_OBJECT_TYPE),
            &if_receiverisincompatible);

  {
    Label done(this);
    const TNode<JSAsyncGeneratorObject> generator = CAST(receiver);
    const TNode<AsyncGeneratorRequest> req =
        AllocateAsyncGeneratorRequest(resume_mode, value, promise);

    AddAsyncGeneratorRequestToQueue(generator, req);

    // Let state be generator.[[AsyncGeneratorState]]
    // If state is not "executing", then
    //     Perform AsyncGeneratorResumeNext(Generator)
    // Check if the {receiver} is running or already closed.
    TNode<Smi> continuation = LoadGeneratorState(generator);

    GotoIf(SmiEqual(continuation,
                    SmiConstant(JSAsyncGeneratorObject::kGeneratorExecuting)),
           &done);

    CallBuiltin(Builtin::kAsyncGeneratorResumeNext, context, generator);

    Goto(&done);
    BIND(&done);
    args->PopAndReturn(promise);
  }

  BIND(&if_receiverisincompatible);
  {
    CallBuiltin(Builtin::kRejectPromise, context, promise,
                MakeTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                              context, StringConstant(method_name), receiver),
                TrueConstant());
    args->PopAndReturn(promise);
  }
}

TNode<AsyncGeneratorRequest>
AsyncGeneratorBuiltinsAssembler::AllocateAsyncGeneratorRequest(
    JSAsyncGeneratorObject::ResumeMode resume_mode, TNode<Object> resume_value,
    TNode<JSPromise> promise) {
  TNode<HeapObject> request = Allocate(AsyncGeneratorRequest::kSize);
  StoreMapNoWriteBarrier(request, RootIndex::kAsyncGeneratorRequestMap);
  StoreObjectFieldNoWriteBarrier(request, AsyncGeneratorRequest::kNextOffset,
                                 UndefinedConstant());
  StoreObjectFieldNoWriteBarrier(request,
                                 AsyncGeneratorRequest::kResumeModeOffset,
                                 SmiConstant(resume_mode));
  StoreObjectFieldNoWriteBarrier(request, AsyncGeneratorRequest::kValueOffset,
                                 resume_value);
  StoreObjectFieldNoWriteBarrier(request, AsyncGeneratorRequest::kPromiseOffset,
                                 promise);
  StoreObjectFieldRoot(request, AsyncGeneratorRequest::kNextOffset,
                       RootIndex::kUndefinedValue);
  return CAST(request);
}

void AsyncGeneratorBuiltinsAssembler::AsyncGeneratorAwaitResume(
    TNode<Context> context,
    TNode<JSAsyncGeneratorObject> async_generator_object, TNode<Object> value,
    JSAsyncGeneratorObject::ResumeMode resume_mode) {
  SetGeneratorNotAwaiting(async_generator_object);

  CSA_SLOW_DCHECK(this, IsGeneratorSuspended(async_generator_object));

  // Remember the {resume_mode} for the {async_generator_object}.
  StoreObjectFieldNoWriteBarrier(async_generator_object,
                                 JSGeneratorObject::kResumeModeOffset,
                                 SmiConstant(resume_mode));

  CallBuiltin(Builtin::kResumeGeneratorTrampoline, context, value,
              async_generator_object);

  TailCallBuiltin(Builtin::kAsyncGeneratorResumeNext, context,
                  async_generator_object);
}

void AsyncGeneratorBuiltinsAssembler::AsyncGeneratorAwaitResumeClosure(
    TNode<Context> context, TNode<Object> value,
    JSAsyncGeneratorObject::ResumeMode resume_mode) {
  const TNode<JSAsyncGeneratorObject> async_generator_object =
      CAST(LoadContextElement(context, Context::EXTENSION_INDEX));

  AsyncGeneratorAwaitResume(context, async_generator_object, value,
                            resume_mode);
}

template <typename Descriptor>
void AsyncGeneratorBuiltinsAssembler::AsyncGeneratorAwait() {
  auto async_generator_object =
      Parameter<JSAsyncGeneratorObject>(Descriptor::kAsyncGeneratorObject);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);

  TNode<AsyncGeneratorRequest> request =
      CAST(LoadFirstAsyncGeneratorRequestFromQueue(async_generator_object));
  TNode<JSPromise> outer_promise = LoadObjectField<JSPromise>(
      request, AsyncGeneratorRequest::kPromiseOffset);

  Await(context, async_generator_object, value, outer_promise,
        RootIndex::kAsyncGeneratorAwaitResolveClosureSharedFun,
        RootIndex::kAsyncGeneratorAwaitRejectClosureSharedFun);
  SetGeneratorAwaiting(async_generator_object);
  Return(UndefinedConstant());
}

void AsyncGeneratorBuiltinsAssembler::AddAsyncGeneratorRequestToQueue(
    TNode<JSAsyncGeneratorObject> generator,
    TNode<AsyncGeneratorRequest> request) {
  TVARIABLE(HeapObject, var_current);
  Label empty(this), loop(this, &var_current), done(this);

  var_current = LoadObjectField<HeapObject>(
      generator, JSAsyncGeneratorObject::kQueueOffset);
  Branch(IsUndefined(var_current.value()), &empty, &loop);

  BIND(&empty);
  {
    StoreObjectField(generator, JSAsyncGeneratorObject::kQueueOffset, request);
    Goto(&done);
  }

  BIND(&loop);
  {
    Label loop_next(this), next_empty(this);
    TNode<AsyncGeneratorRequest> current = CAST(var_current.value());
    TNode<HeapObject> next = LoadObjectField<HeapObject>(
        current, AsyncGeneratorRequest::kNextOffset);

    Branch(IsUndefined(next), &next_empty, &loop_next);
    BIND(&next_empty);
    {
      StoreObjectField(current, AsyncGeneratorRequest::kNextOffset, request);
      Goto(&done);
    }

    BIND(&loop_next);
    {
      var_current = next;
      Goto(&loop);
    }
  }
  BIND(&done);
}

TNode<AsyncGeneratorRequest>
AsyncGeneratorBuiltinsAssembler::TakeFirstAsyncGeneratorRequestFromQueue(
    TNode<JSAsyncGeneratorObject> generator) {
  // Removes and returns the first AsyncGeneratorRequest from a
  // JSAsyncGeneratorObject's queue. Asserts that the queue is not empty.
  TNode<AsyncGeneratorRequest> request = LoadObjectField<AsyncGeneratorRequest>(
      generator, JSAsyncGeneratorObject::kQueueOffset);

  TNode<Object> next =
      LoadObjectField(request, AsyncGeneratorRequest::kNextOffset);

  StoreObjectField(generator, JSAsyncGeneratorObject::kQueueOffset, next);
  return request;
}

void AsyncGeneratorBuiltinsAssembler::AsyncGeneratorReturnClosedReject(
    TNode<Context> context, TNode<JSAsyncGeneratorObject> generator,
    TNode<Object> value) {
  SetGeneratorNotAwaiting(generator);

  // https://tc39.github.io/proposal-async-iteration/
  //    #async-generator-resume-next-return-processor-rejected step 2:
  // Return ! AsyncGeneratorReject(_F_.[[Generator]], _reason_).
  CallBuiltin(Builtin::kAsyncGeneratorReject, context, generator, value);

  TailCallBuiltin(Builtin::kAsyncGeneratorResumeNext, context, generator);
}
}  // namespace

// https://tc39.github.io/proposal-async-iteration/
// Section #sec-asyncgenerator-prototype-next
TF_BUILTIN(AsyncGeneratorPrototypeNext, AsyncGeneratorBuiltinsAssembler) {
  const int kValueArg = 0;

  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  TNode<Object> generator = args.GetReceiver();
  TNode<Object> value = args.GetOptionalArgumentValue(kValueArg);
  auto context = Parameter<Context>(Descriptor::kContext);

  AsyncGeneratorEnqueue(&args, context, generator, value,
                        JSAsyncGeneratorObject::kNext,
                        "[AsyncGenerator].prototype.next");
}

// https://tc39.github.io/proposal-async-iteration/
// Section #sec-asyncgenerator-prototype-return
TF_BUILTIN(AsyncGeneratorPrototypeReturn, AsyncGeneratorBuiltinsAssembler) {
  const int kValueArg = 0;

  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  TNode<Object> generator = args.GetReceiver();
  TNode<Object> value = args.GetOptionalArgumentValue(kValueArg);
  auto context = Parameter<Context>(Descriptor::kContext);

  AsyncGeneratorEnqueue(&args, context, generator, value,
                        JSAsyncGeneratorObject::kReturn,
                        "[AsyncGenerator].prototype.return");
}

// https://tc39.github.io/proposal-async-iteration/
// Section #sec-asyncgenerator-prototype-throw
TF_BUILTIN(AsyncGeneratorPrototypeThrow, AsyncGeneratorBuiltinsAssembler) {
  const int kValueArg = 0;

  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);

  TNode<Object> generator = args.GetReceiver();
  TNode<Object> value = args.GetOptionalArgumentValue(kValueArg);
  auto context = Parameter<Context>(Descriptor::kContext);

  AsyncGeneratorEnqueue(&args, context, generator, value,
                        JSAsyncGeneratorObject::kThrow,
                        "[AsyncGenerator].prototype.throw");
}

TF_BUILTIN(AsyncGeneratorAwaitResolveClosure, AsyncGeneratorBuiltinsAssembler) {
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);
  AsyncGeneratorAwaitResumeClosure(context, value,
                                   JSAsyncGeneratorObject::kNext);
}

TF_BUILTIN(AsyncGeneratorAwaitRejectClosure, AsyncGeneratorBuiltinsAssembler) {
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);
  // Restart in Rethrow mode, as this exception was already thrown and we don't
  // want to trigger a second debug break event or change the message location.
  AsyncGeneratorAwaitResumeClosure(context, value,
                                   JSAsyncGeneratorObject::kRethrow);
}

TF_BUILTIN(AsyncGeneratorAwait, AsyncGeneratorBuiltinsAssembler) {
  AsyncGeneratorAwait<Descriptor>();
}

TF_BUILTIN(AsyncGeneratorResumeNext, AsyncGeneratorBuiltinsAssembler) {
  const auto generator =
      Parameter<JSAsyncGeneratorObject>(Descriptor::kGenerator);
  const auto context = Parameter<Context>(Descriptor::kContext);

  // The penultimate step of proposal-async-iteration/#sec-asyncgeneratorresolve
  // and proposal-async-iteration/#sec-asyncgeneratorreject both recursively
  // invoke AsyncGeneratorResumeNext() again.
  //
  // This implementation does not implement this recursively, but instead
  // performs a loop in AsyncGeneratorResumeNext, which  continues as long as
  // there is an AsyncGeneratorRequest in the queue, and as long as the
  // generator is not suspended due to an AwaitExpression.
  TVARIABLE(Smi, var_state, LoadGeneratorState(generator));
  TVARIABLE(HeapObject, var_next,
            LoadFirstAsyncGeneratorRequestFromQueue(generator));
  Label start(this, {&var_state, &var_next});
  Goto(&start);
  BIND(&start);

  CSA_DCHECK(this, IsGeneratorNotExecuting(generator));

  // Stop resuming if suspended for Await.
  ReturnIf(IsGeneratorAwaiting(generator), UndefinedConstant());

  // Stop resuming if request queue is empty.
  ReturnIf(IsUndefined(var_next.value()), UndefinedConstant());

  const TNode<AsyncGeneratorRequest> next = CAST(var_next.value());
  const TNode<Smi> resume_type = LoadResumeTypeFromAsyncGeneratorRequest(next);

  Label if_abrupt(this), if_normal(this), resume_generator(this);
  Branch(IsAbruptResumeType(resume_type), &if_abrupt, &if_normal);
  BIND(&if_abrupt);
  {
    Label settle_promise(this), if_return(this), if_throw(this);
    GotoIfNot(IsGeneratorStateSuspendedAtStart(var_state.value()),
              &settle_promise);
    CloseGenerator(generator);
    var_state = SmiConstant(JSGeneratorObject::kGeneratorClosed);
    Goto(&settle_promise);

    BIND(&settle_promise);
    TNode<Object> next_value = LoadValueFromAsyncGeneratorRequest(next);
    Branch(SmiEqual(resume_type, SmiConstant(JSGeneratorObject::kReturn)),
           &if_return, &if_throw);

    BIND(&if_return);
    // For "return" completions, await the sent value. If the Await succeeds,
    // and the generator is not closed, resume the generator with a "return"
    // completion to allow `finally` blocks to be evaluated. Otherwise, perform
    // AsyncGeneratorResolve(awaitedValue, true). If the await fails and the
    // generator is not closed, resume the generator with a "throw" completion.
    // If the generator was closed, perform AsyncGeneratorReject(thrownValue).
    // In all cases, the last step is to call AsyncGeneratorResumeNext.
    TailCallBuiltin(Builtin::kAsyncGeneratorReturn, context, generator,
                    next_value);

    BIND(&if_throw);
    GotoIfNot(IsGeneratorStateClosed(var_state.value()), &resume_generator);
    CallBuiltin(Builtin::kAsyncGeneratorReject, context, generator, next_value);
    var_next = LoadFirstAsyncGeneratorRequestFromQueue(generator);
    Goto(&start);
  }

  BIND(&if_normal);
  {
    GotoIfNot(IsGeneratorStateClosed(var_state.value()), &resume_generator);
    CallBuiltin(Builtin::kAsyncGeneratorResolve, context, generator,
                UndefinedConstant(), TrueConstant());
    var_state = LoadGeneratorState(generator);
    var_next = LoadFirstAsyncGeneratorRequestFromQueue(generator);
    Goto(&start);
  }

  BIND(&resume_generator);
  {
    // Remember the {resume_type} for the {generator}.
    StoreObjectFieldNoWriteBarrier(
        generator, JSGeneratorObject::kResumeModeOffset, resume_type);

    CallBuiltin(Builtin::kResumeGeneratorTrampoline, context,
                LoadValueFromAsyncGeneratorRequest(next), generator);
    var_state = LoadGeneratorState(generator);
    var_next = LoadFirstAsyncGeneratorRequestFromQueue(generator);
    Goto(&start);
  }
}

TF_BUILTIN(AsyncGeneratorResolve, AsyncGeneratorBuiltinsAssembler) {
  const auto generator =
      Parameter<JSAsyncGeneratorObject>(Descriptor::kGenerator);
  const auto value = Parameter<Object>(Descriptor::kValue);
  const auto done = Parameter<Object>(Descriptor::kDone);
  const auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, Word32BinaryNot(IsGeneratorAwaiting(generator)));

  // This operation should be called only when the `value` parameter has been
  // Await-ed. Typically, this means `value` is not a JSPromise value. However,
  // it may be a JSPromise value whose "then" method has been overridden to a
  // non-callable value. This can't be checked with assertions due to being
  // observable, but keep it in mind.

  const TNode<AsyncGeneratorRequest> next =
      TakeFirstAsyncGeneratorRequestFromQueue(generator);
  const TNode<JSPromise> promise = LoadPromiseFromAsyncGeneratorRequest(next);

  // Let iteratorResult be CreateIterResultObject(value, done).
  const TNode<HeapObject> iter_result = Allocate(JSIteratorResult::kSize);
  {
    TNode<Map> map = CAST(LoadContextElement(
        LoadNativeContext(context), Context::ITERATOR_RESULT_MAP_INDEX));
    StoreMapNoWriteBarrier(iter_result, map);
    StoreObjectFieldRoot(iter_result, JSIteratorResult::kPropertiesOrHashOffset,
                         RootIndex::kEmptyFixedArray);
    StoreObjectFieldRoot(iter_result, JSIteratorResult::kElementsOffset,
                         RootIndex::kEmptyFixedArray);
    StoreObjectFieldNoWriteBarrier(iter_result, JSIteratorResult::kValueOffset,
                                   value);
    StoreObjectFieldNoWriteBarrier(iter_result, JSIteratorResult::kDoneOffset,
                                   done);
  }

  // We know that {iter_result} itself doesn't have any "then" property (a
  // freshly allocated IterResultObject only has "value" and "done" properties)
  // and we also know that the [[Prototype]] of {iter_result} is the intrinsic
  // %ObjectPrototype%. So we can skip the [[Resolve]] logic here completely
  // and directly call into the FulfillPromise operation if we can prove
  // that the %ObjectPrototype% also doesn't have any "then" property. This
  // is guarded by the Promise#then() protector.
  // If the PromiseHooks are enabled, we cannot take the shortcut here, since
  // the "promiseResolve" hook would not be fired otherwise.
  Label if_fast(this), if_slow(this, Label::kDeferred), return_promise(this);
  GotoIfForceSlowPath(&if_slow);
  GotoIf(IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate(), &if_slow);
  Branch(IsPromiseThenProtectorCellInvalid(), &if_slow, &if_fast);

  BIND(&if_fast);
  {
    // Skip the "then" on {iter_result} and directly fulfill the {promise}
    // with the {iter_result}.
    CallBuiltin(Builtin::kFulfillPromise, context, promise, iter_result);
    Goto(&return_promise);
  }

  BIND(&if_slow);
  {
    // Perform Call(promiseCapability.[[Resolve]], undefined, «iteratorResult»).
    CallBuiltin(Builtin::kResolvePromise, context, promise, iter_result);
    Goto(&return_promise);
  }

  // Per spec, AsyncGeneratorResolve() returns undefined. However, for the
  // benefit of %TraceExit(), return the Promise.
  BIND(&return_promise);
  Return(promise);
}

TF_BUILTIN(AsyncGeneratorReject, AsyncGeneratorBuiltinsAssembler) {
  const auto generator =
      Parameter<JSAsyncGeneratorObject>(Descriptor::kGenerator);
  const auto value = Parameter<Object>(Descriptor::kValue);
  const auto context = Parameter<Context>(Descriptor::kContext);

  TNode<AsyncGeneratorRequest> next =
      TakeFirstAsyncGeneratorRequestFromQueue(generator);
  TNode<JSPromise> promise = LoadPromiseFromAsyncGeneratorRequest(next);

  // No debug event needed, there was already a debug event that got us here.
  Return(CallBuiltin(Builtin::kRejectPromise, context, promise, value,
                     FalseConstant()));
}

TF_BUILTIN(AsyncGeneratorYieldWithAwait, AsyncGeneratorBuiltinsAssembler) {
  const auto generator = Parameter<JSGeneratorObject>(Descriptor::kGenerator);
  const auto value = Parameter<Object>(Descriptor::kValue);
  const auto context = Parameter<Context>(Descriptor::kContext);

  const TNode<AsyncGeneratorRequest> request =
      CAST(LoadFirstAsyncGeneratorRequestFromQueue(generator));
  const TNode<JSPromise> outer_promise =
      LoadPromiseFromAsyncGeneratorRequest(request);

  Await(context, generator, value, outer_promise,
        RootIndex::kAsyncGeneratorYieldWithAwaitResolveClosureSharedFun,
        RootIndex::kAsyncGeneratorAwaitRejectClosureSharedFun);
  SetGeneratorAwaiting(generator);
  Return(UndefinedConstant());
}

TF_BUILTIN(AsyncGeneratorYieldWithAwaitResolveClosure,
           AsyncGeneratorBuiltinsAssembler) {
  const auto context = Parameter<Context>(Descriptor::kContext);
  const auto value = Parameter<Object>(Descriptor::kValue);
  const TNode<JSAsyncGeneratorObject> generator =
      CAST(LoadContextElement(context, Context::EXTENSION_INDEX));

  SetGeneratorNotAwaiting(generator);

  // Per proposal-async-iteration/#sec-asyncgeneratoryield step 9
  // Return ! AsyncGeneratorResolve(_F_.[[Generator]], _value_, *false*).
  CallBuiltin(Builtin::kAsyncGeneratorResolve, context, generator, value,
              FalseConstant());

  TailCallBuiltin(Builtin::kAsyncGeneratorResumeNext, context, generator);
}

TF_BUILTIN(AsyncGeneratorReturn, AsyncGeneratorBuiltinsAssembler) {
  // AsyncGeneratorReturn is called when resuming requests with "return" resume
  // modes. It is similar to AsyncGeneratorAwait(), but selects different
  // resolve/reject closures depending on whether or not the generator is marked
  // as closed, and handles exception on Await explicitly.
  //
  // In particular, non-closed generators will resume the generator with either
  // "return" or "throw" resume modes, allowing finally blocks or catch blocks
  // to be evaluated, as if the `await` were performed within the body of the
  // generator. (per proposal-async-iteration/#sec-asyncgeneratoryield step 8.b)
  //
  // Closed generators do not resume the generator in the resolve/reject
  // closures, but instead simply perform AsyncGeneratorResolve or
  // AsyncGeneratorReject with the awaited value
  // (per proposal-async-iteration/#sec-asyncgeneratorresumenext step 10.b.i)
  //
  // In all cases, the final step is to jump back to AsyncGeneratorResumeNext.
  const auto generator =
      Parameter<JSAsyncGeneratorObject>(Descriptor::kGenerator);
  const auto value = Parameter<Object>(Descriptor::kValue);
  const TNode<AsyncGeneratorRequest> req =
      CAST(LoadFirstAsyncGeneratorRequestFromQueue(generator));

  const TNode<Smi> state = LoadGeneratorState(generator);
  auto MakeClosures = [&](TNode<Context> context,
                          TNode<NativeContext> native_context) {
    TVARIABLE(JSFunction, var_on_resolve);
    TVARIABLE(JSFunction, var_on_reject);
    Label closed(this), not_closed(this), done(this);
    Branch(IsGeneratorStateClosed(state), &closed, &not_closed);

    BIND(&closed);
    var_on_resolve = AllocateRootFunctionWithContext(
        RootIndex::kAsyncGeneratorReturnClosedResolveClosureSharedFun, context,
        native_context);
    var_on_reject = AllocateRootFunctionWithContext(
        RootIndex::kAsyncGeneratorReturnClosedRejectClosureSharedFun, context,
        native_context);
    Goto(&done);

    BIND(&not_closed);
    var_on_resolve = AllocateRootFunctionWithContext(
        RootIndex::kAsyncGeneratorReturnResolveClosureSharedFun, context,
        native_context);
    var_on_reject = AllocateRootFunctionWithContext(
        RootIndex::kAsyncGeneratorAwaitRejectClosureSharedFun, context,
        native_context);
    Goto(&done);

    BIND(&done);
    return std::make_pair(var_on_resolve.value(), var_on_reject.value());
  };

  SetGeneratorAwaiting(generator);
  auto context = Parameter<Context>(Descriptor::kContext);
  const TNode<JSPromise> outer_promise =
      LoadPromiseFromAsyncGeneratorRequest(req);

  Label done(this), await_exception(this, Label::kDeferred),
      closed_await_exception(this, Label::kDeferred);
  TVARIABLE(Object, var_exception);
  {
    compiler::ScopedExceptionHandler handler(this, &await_exception,
                                             &var_exception);
    Await(context, generator, value, outer_promise, MakeClosures);
  }
  Goto(&done);

  BIND(&await_exception);
  {
    GotoIf(IsGeneratorStateClosed(state), &closed_await_exception);
    // Tail call to AsyncGeneratorResumeNext
    AsyncGeneratorAwaitResume(context, generator, var_exception.value(),
                              JSGeneratorObject::kThrow);
  }

  BIND(&closed_await_exception);
  {
    // Tail call to AsyncGeneratorResumeNext
    AsyncGeneratorReturnClosedReject(context, generator, var_exception.value());
  }

  BIND(&done);
  Return(UndefinedConstant());
}

// On-resolve closure for Await in AsyncGeneratorReturn
// Resume the generator with "return" resume_mode, and finally perform
// AsyncGeneratorResumeNext. Per
// proposal-async-iteration/#sec-asyncgeneratoryield step 8.e
TF_BUILTIN(AsyncGeneratorReturnResolveClosure,
           AsyncGeneratorBuiltinsAssembler) {
  const auto context = Parameter<Context>(Descriptor::kContext);
  const auto value = Parameter<Object>(Descriptor::kValue);
  AsyncGeneratorAwaitResumeClosure(context, value, JSGeneratorObject::kReturn);
}

// On-resolve closure for Await in AsyncGeneratorReturn
// Perform AsyncGeneratorResolve({awaited_value}, true) and finally perform
// AsyncGeneratorResumeNext.
TF_BUILTIN(AsyncGeneratorReturnClosedResolveClosure,
           AsyncGeneratorBuiltinsAssembler) {
  const auto context = Parameter<Context>(Descriptor::kContext);
  const auto value = Parameter<Object>(Descriptor::kValue);
  const TNode<JSAsyncGeneratorObject> generator =
      CAST(LoadContextElement(context, Context::EXTENSION_INDEX));

  SetGeneratorNotAwaiting(generator);

  // https://tc39.github.io/proposal-async-iteration/
  //    #async-generator-resume-next-return-processor-fulfilled step 2:
  //  Return ! AsyncGeneratorResolve(_F_.[[Generator]], _value_, *true*).
  CallBuiltin(Builtin::kAsyncGeneratorResolve, context, generator, value,
              TrueConstant());

  TailCallBuiltin(Builtin::kAsyncGeneratorResumeNext, context, generator);
}

TF_BUILTIN(AsyncGeneratorReturnClosedRejectClosure,
           AsyncGeneratorBuiltinsAssembler) {
  const auto context = Parameter<Context>(Descriptor::kContext);
  const auto value = Parameter<Object>(Descriptor::kValue);
  const TNode<JSAsyncGeneratorObject> generator =
      CAST(LoadContextElement(context, Context::EXTENSION_INDEX));

  AsyncGeneratorReturnClosedReject(context, generator, value);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""

```