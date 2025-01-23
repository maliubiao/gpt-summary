Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Understand the Goal:** The request asks for a functional overview of `builtins-async-generator-gen.cc`. Key aspects to identify are: what it does, how it relates to JavaScript, example usage, potential logic, and common errors.

2. **Initial Scan - Keywords and Structure:**  Skim the code for recognizable keywords and structural elements. I see:
    * `Copyright 2017 the V8 project authors`: Confirms it's V8 code.
    * `#include`: Indicates dependencies on other V8 components. Pay attention to `builtins-async-gen.h`, `builtins-utils-gen.h`, `builtins.h`, `code-stub-assembler-inl.h`, `frames-inl.h`, `js-generator.h`, `js-promise.h`. These suggest it deals with asynchronous generators, utilities, built-in functions, code generation, execution frames, generator objects, and promises.
    * `namespace v8 { namespace internal {`:  Indicates it's part of V8's internal implementation.
    * `class AsyncGeneratorBuiltinsAssembler`:  This is the core of the file. The name suggests it's responsible for assembling built-in functions related to asynchronous generators. The inheritance from `AsyncBuiltinsAssembler` is also a clue.
    * `TF_BUILTIN(...)`: This macro is a strong indicator of built-in function definitions within V8. The names (`AsyncGeneratorPrototypeNext`, `AsyncGeneratorPrototypeReturn`, `AsyncGeneratorPrototypeThrow`, etc.) clearly map to JavaScript's async generator methods.
    *  Inline functions like `LoadGeneratorState`, `IsGeneratorStateClosed`, etc. are helper functions for working with the internal state of generator objects.

3. **Identify Key Functionality Areas:** Based on the `TF_BUILTIN` definitions and the helper functions, group the functionality:
    * **Async Generator Prototype Methods:** `next`, `return`, `throw`. These directly correspond to JavaScript methods.
    * **Async Generator Await:**  Functions related to the `await` keyword within an async generator (`AsyncGeneratorAwait`, `AsyncGeneratorAwaitResolveClosure`, `AsyncGeneratorAwaitRejectClosure`).
    * **Async Generator Resumption:**  How the generator progresses after an `await` (`AsyncGeneratorResumeNext`).
    * **Async Generator Resolution/Rejection:** Handling the successful completion or erroring of the asynchronous operation (`AsyncGeneratorResolve`, `AsyncGeneratorReject`).
    * **Internal State Management:** Functions for accessing and modifying the internal state of async generator objects (e.g., `LoadGeneratorState`, `IsGeneratorAwaiting`, `SetGeneratorAwaiting`).
    * **Request Queue Management:** Handling the queue of pending `next`, `return`, or `throw` operations (`AsyncGeneratorEnqueue`, `AddAsyncGeneratorRequestToQueue`, `TakeFirstAsyncGeneratorRequestFromQueue`).

4. **Relate to JavaScript:**  For each functional area, think about the corresponding JavaScript behavior.
    * `AsyncGeneratorPrototypeNext`:  Corresponds to calling `asyncGenerator.next()`.
    * `AsyncGeneratorPrototypeReturn`: Corresponds to calling `asyncGenerator.return(value)`.
    * `AsyncGeneratorPrototypeThrow`: Corresponds to calling `asyncGenerator.throw(error)`.
    * `await`: The `AsyncGeneratorAwait` family of functions handles the logic when an `await` is encountered.

5. **Illustrate with JavaScript Examples:** Create simple JavaScript code snippets to demonstrate the purpose of the built-in functions. This clarifies the connection between the C++ implementation and the user-facing JavaScript.

6. **Infer Logic and Data Flow:**  Examine the helper functions and the `TF_BUILTIN` implementations to understand the flow of execution. Focus on:
    * How requests are queued and processed.
    * How the generator's state is managed (suspended, executing, closed).
    * How promises are involved in the asynchronous operations.
    * The role of the "resume mode" (`kNext`, `kReturn`, `kThrow`).

7. **Identify Potential Errors:** Think about common mistakes developers might make when working with async generators. This often involves misunderstanding their asynchronous nature or how they interact with promises.
    * Calling `next()`, `return()`, or `throw()` after the generator has closed.
    * Assuming synchronous execution.
    * Incorrectly handling errors.

8. **Address Specific Questions:** Go back to the original prompt and make sure all points are covered:
    * **Functionality Listing:** Explicitly list the identified functionalities.
    * **Torque Source:**  Note that the `.cc` extension means it's not Torque.
    * **JavaScript Relation and Examples:** Provide the JavaScript examples.
    * **Logic and Data Flow (Hypothetical Input/Output):** Create a simple scenario and trace the execution through the built-in functions, describing the expected input and output at key stages. Even if it's a simplified scenario, it helps illustrate the core mechanisms.
    * **Common Programming Errors:** Give concrete examples of errors and explain why they occur.

9. **Refine and Organize:** Structure the answer clearly with headings and bullet points. Use precise language and avoid jargon where possible. Ensure that the explanation flows logically and is easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This seems complicated."  **Correction:** Break it down into smaller, manageable parts (the different built-in functions and helper functions).
* **Potential misunderstanding:**  Assuming all `TF_BUILTIN` functions are directly called by JavaScript. **Correction:** Realize that some are internal closures or trampoline functions used by the engine.
* **Realization:** The request queue is crucial for understanding how concurrent calls to `next`, `return`, and `throw` are handled. Focus on explaining the enqueueing and dequeueing process.
* **Emphasis:** Highlight the state transitions of the async generator object.

By following these steps and continuously refining the understanding, a comprehensive and accurate explanation of the V8 source code can be generated.
这个文件 `v8/src/builtins/builtins-async-generator-gen.cc` 是 V8 JavaScript 引擎中用于实现 **异步生成器 (Async Generator)** 相关内置函数的 C++ 代码。

**功能列表:**

这个文件主要负责实现以下与异步生成器相关的核心功能：

1. **异步生成器原型方法 (Async Generator Prototype Methods):**
   - `AsyncGeneratorPrototypeNext`:  实现了 `AsyncGenerator.prototype.next()` 方法的逻辑。当异步生成器的 `next()` 方法被调用时，它会将一个“请求”放入异步生成器的内部队列中，并返回一个 Promise。这个 Promise 将在异步生成器内部的操作完成后被 resolve 或 reject。
   - `AsyncGeneratorPrototypeReturn`: 实现了 `AsyncGenerator.prototype.return(value)` 方法的逻辑。它也向异步生成器队列添加一个请求，指示生成器以指定的值完成并关闭。
   - `AsyncGeneratorPrototypeThrow`: 实现了 `AsyncGenerator.prototype.throw(error)` 方法的逻辑。它向异步生成器队列添加一个请求，指示生成器抛出一个错误。

2. **异步生成器的状态管理:**
   - 提供了一些辅助函数来检查和修改异步生成器的内部状态，例如：
     - `LoadGeneratorState`: 加载生成器的当前状态。
     - `IsGeneratorStateClosed`: 判断生成器状态是否为已关闭。
     - `IsGeneratorSuspended`: 判断生成器是否处于暂停状态。
     - `IsGeneratorAwaiting`: 判断生成器是否正在等待一个 Promise。
     - `SetGeneratorAwaiting` 和 `SetGeneratorNotAwaiting`: 设置生成器是否正在等待状态。
     - `CloseGenerator`: 关闭生成器。

3. **异步生成器请求队列管理:**
   - 实现了管理异步生成器内部请求队列的逻辑。当 `next()`, `return()`, 或 `throw()` 被调用时，会创建一个 `AsyncGeneratorRequest` 对象并添加到队列中。
   - `AsyncGeneratorEnqueue`:  负责将请求添加到队列中，并触发异步生成器的恢复执行（如果它当前没有执行）。
   - `AddAsyncGeneratorRequestToQueue`: 将 `AsyncGeneratorRequest` 添加到队列的末尾。
   - `TakeFirstAsyncGeneratorRequestFromQueue`: 从队列的头部移除并返回第一个 `AsyncGeneratorRequest`。
   - `AllocateAsyncGeneratorRequest`:  分配一个新的 `AsyncGeneratorRequest` 对象。

4. **异步生成器的恢复和执行:**
   - `AsyncGeneratorResumeNext`:  这是异步生成器执行的核心逻辑。它从请求队列中取出第一个请求，并根据请求的类型（`next`, `return`, `throw`）以及生成器的当前状态来恢复生成器的执行。
   - `AsyncGeneratorAwait`:  处理 `await` 关键字在异步生成器中的行为。当在异步生成器内部遇到 `await` 时，会调用此函数，它会暂停生成器的执行，并等待被 `await` 的 Promise 完成。
   - `AsyncGeneratorAwaitResolveClosure` 和 `AsyncGeneratorAwaitRejectClosure`:  当被 `await` 的 Promise resolve 或 reject 时调用的回调函数，用于恢复生成器的执行。
   - `AsyncGeneratorYieldWithAwait`: 处理 `yield await` 表达式。

5. **异步生成器的完成和错误处理:**
   - `AsyncGeneratorResolve`:  当异步生成器成功产生一个值时调用，它会创建一个迭代器结果对象，并 resolve 与当前请求关联的 Promise。
   - `AsyncGeneratorReject`:  当异步生成器发生错误时调用，它会 reject 与当前请求关联的 Promise。
   - `AsyncGeneratorReturnClosedReject`:  当在生成器已关闭的状态下尝试 `return` 操作时，拒绝关联的 Promise。

**关于源代码的说明:**

- **不是 Torque 代码:**  文件名以 `.cc` 结尾，这表明它是标准的 C++ 源代码，而不是 V8 的 Torque 语言源代码（以 `.tq` 结尾）。Torque 是一种用于编写 V8 内置函数的领域特定语言，旨在提高性能和安全性。
- **与 JavaScript 功能的关系:**  这个文件直接实现了 JavaScript 中异步生成器的核心行为。当你在 JavaScript 中使用 `async function*` 定义异步生成器并调用其 `next()`, `return()`, 或 `throw()` 方法，或者在异步生成器内部使用 `await` 或 `yield await` 关键字时，V8 引擎会执行这个文件中定义的 C++ 代码。

**JavaScript 示例:**

```javascript
async function* myAsyncGenerator() {
  console.log("开始执行");
  yield 1;
  console.log("第一次 yield 后");
  await Promise.resolve(2);
  console.log("await 完成后");
  yield 3;
  console.log("第二次 yield 后");
  return 4;
}

async function main() {
  const generator = myAsyncGenerator();

  console.log("调用 next()");
  let result1 = await generator.next();
  console.log("next() 结果:", result1); // { value: 1, done: false }

  console.log("再次调用 next()");
  let result2 = await generator.next();
  console.log("next() 结果:", result2); // { value: 3, done: false }

  console.log("调用 return(10)");
  let result3 = await generator.return(10);
  console.log("return() 结果:", result3); // { value: 10, done: true }

  console.log("再次调用 next()");
  let result4 = await generator.next();
  console.log("next() 结果:", result4); // { value: undefined, done: true }
}

main();
```

在这个例子中，`v8/src/builtins/builtins-async-generator-gen.cc` 中的代码会被 V8 引擎调用来处理以下操作：

- 当 `generator.next()` 被调用时，`AsyncGeneratorPrototypeNext` 会被执行，将请求添加到队列并返回一个 Promise。
- 当异步生成器内部遇到 `yield 1` 时，执行会暂停，`AsyncGeneratorResolve` 会被调用来 resolve 第一个 Promise。
- 当遇到 `await Promise.resolve(2)` 时，`AsyncGeneratorAwait` 会被调用，暂停执行直到 Promise resolve。`AsyncGeneratorAwaitResolveClosure` 会在 Promise resolve 后恢复执行。
- 当遇到 `return 4` 时，`AsyncGeneratorReturn` 相关的逻辑会被执行。
- 当 `generator.return(10)` 被调用时，`AsyncGeneratorPrototypeReturn` 会被执行。

**代码逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码：

```javascript
async function* ag() {
  console.log("开始");
  const value = await Promise.resolve(5);
  console.log("await 完成，value:", value);
  yield value;
  console.log("yield 后");
}

async function main() {
  const gen = ag();
  console.log("第一次 next()");
  const res1 = await gen.next();
  console.log("第一次 next() 结果:", res1);
}

main();
```

**假设的 V8 执行流程和输入/输出:**

1. **`main()` 函数开始执行。**
2. **`ag()` 函数被调用，创建一个异步生成器对象 `gen`。**
   - 输入：无
   - 输出：一个指向新创建的 `JSAsyncGeneratorObject` 的指针。
3. **`main()` 函数调用 `gen.next()`。**
   - `AsyncGeneratorPrototypeNext` 被调用。
   - 输入：`gen` 对象。
   - 输出：一个 Promise 对象（与第一次 `next()` 调用关联）。
4. **`AsyncGeneratorEnqueue` 将一个 `kNext` 类型的 `AsyncGeneratorRequest` 添加到 `gen` 的请求队列中。**
5. **由于生成器当前没有执行，`AsyncGeneratorResumeNext` 被调用。**
6. **`AsyncGeneratorResumeNext` 从队列中取出第一个请求 (`kNext`)。**
7. **生成器内部开始执行，遇到 `await Promise.resolve(5)`。**
   - `AsyncGeneratorAwait` 被调用。
   - 输入：`gen` 对象，Promise 对象 (由 `Promise.resolve(5)` 创建)。
   - 输出：无 (生成器暂停)。
8. **V8 引擎开始等待 `Promise.resolve(5)` resolve。**
9. **`Promise.resolve(5)` resolve，值为 `5`。**
10. **`AsyncGeneratorAwaitResolveClosure` 被调用。**
    - 输入：上下文，值 `5`。
    - 输出：无。
11. **`AsyncGeneratorAwaitResume` 被调用，恢复生成器的执行。**
12. **生成器继续执行，`value` 被赋值为 `5`。**
13. **`console.log("await 完成，value:", value)` 执行，输出 "await 完成，value: 5"。**
14. **遇到 `yield value`。**
   - `AsyncGeneratorResolve` 被调用。
   - 输入：`gen` 对象，值 `5`，`done: false`。
   - 输出：与第一次 `next()` 调用关联的 Promise 被 resolve，值为 `{ value: 5, done: false }`。
15. **`main()` 函数中的 `await gen.next()` 完成，`res1` 被赋值为 `{ value: 5, done: false }`。**
16. **`console.log("第一次 next() 结果:", res1)` 执行，输出 "第一次 next() 结果: { value: 5, done: false }"。**

**用户常见的编程错误示例:**

1. **在异步生成器关闭后调用 `next()`, `return()`, 或 `throw()`:**

   ```javascript
   async function* ag() {
     yield 1;
     return 2;
   }

   async function main() {
     const gen = ag();
     await gen.next(); // { value: 1, done: false }
     await gen.next(); // { value: 2, done: true }  生成器已关闭
     await gen.next(); // 仍然会返回一个 Promise，但它的 resolved 值会是 { value: undefined, done: true }
   }
   ```

   V8 的代码会处理这种情况，但理解生成器的生命周期很重要。在生成器关闭后调用这些方法不会抛出错误，而是会返回一个已完成的迭代器结果。

2. **忘记 `await` 异步生成器 `next()` 返回的 Promise:**

   ```javascript
   async function* ag() {
     await new Promise(resolve => setTimeout(resolve, 100));
     yield 1;
   }

   async function main() {
     const gen = ag();
     gen.next(); // 没有 await，Promise 可能仍在 pending 状态
     console.log("next() 调用后"); // 这行代码可能会在生成器 yield 之前执行
   }
   ```

   这是异步编程中常见的错误。没有 `await`，`gen.next()` 返回的 Promise 不会被等待，导致后续代码在异步操作完成之前执行。

3. **在异步生成器内部错误地处理 Promise 的 rejection:**

   ```javascript
   async function* ag() {
     try {
       await Promise.reject("出错了");
     } catch (error) {
       console.error("捕获到错误:", error);
     }
     yield 1;
   }

   async function main() {
     const gen = ag();
     await gen.next();
   }
   ```

   V8 的 `AsyncGeneratorAwaitRejectClosure` 会处理 Promise 的 rejection，并将控制权传递回生成器，允许 `try...catch` 块捕获错误。理解异步生成器如何与 Promise 交互对于正确处理错误至关重要。

总而言之，`v8/src/builtins/builtins-async-generator-gen.cc` 是 V8 引擎中实现异步生成器核心功能的关键组成部分，它负责处理异步生成器的状态管理、请求队列、执行恢复以及与 Promise 的交互。 理解这个文件中的代码有助于深入理解 JavaScript 异步生成器的工作原理。

### 提示词
```
这是目录为v8/src/builtins/builtins-async-generator-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-async-generator-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```