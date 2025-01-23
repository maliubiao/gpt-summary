Response:
Let's break down the thought process for analyzing this `script_iterator.cc` file.

1. **Initial Understanding - What is it about?**  The filename itself gives a strong clue: `script_iterator`. Combined with the Chromium Blink context, this immediately suggests it's about how JavaScript iterators are handled within the engine. The `#include` statements confirm this, referencing V8, script concepts (like `ScriptController`, `ScriptFunction`, `ScriptPromise`), and general binding infrastructure.

2. **Core Functionality Identification -  The `ScriptIterator` Class:**  The core of the file is the `ScriptIterator` class. The static `FromIterable` method is the entry point for creating a `ScriptIterator` from a JavaScript iterable. The `Next` method is clearly how you advance the iterator and get the next value. The `CloseSync` and `CloseAsync` methods handle the closing of iterators, which is crucial for resource management and proper termination.

3. **Relating to JavaScript Concepts:** This is where the connection to JavaScript's iterator protocol becomes paramount. I'd be thinking:
    * **`@@iterator` and `@@asyncIterator`:** The `FromIterable` method explicitly checks for these symbols. This is the fundamental mechanism in JavaScript for making an object iterable.
    * **`next()` method:** The `Next` method directly interacts with the `next()` method of the underlying JavaScript iterator object.
    * **`return()` method:**  The `CloseSync` and `CloseAsync` methods deal with the optional `return()` method, which allows for cleanup.
    * **Iterator Result Object (`{ value, done }`):** The `Next` method in the synchronous case explicitly looks for `value` and `done` properties.
    * **Promises (for Async Iterators):**  The `CloseAsync` method and the handling within the `Next` method for asynchronous iterators strongly indicate the involvement of Promises. This aligns with how async iterators work in JavaScript.

4. **Code Walkthrough - Key Sections:** I'd then go through the code, focusing on the critical parts of each method:
    * **`FromIterable`:** How it retrieves the iterator method (`@@iterator` or `@@asyncIterator`), handles the case where it's missing, calls the method to get the iterator object, and extracts the `next` method. The special handling for async iterators and the TODO about falling back to sync iterators are important details.
    * **`Next`:** How it calls the `next()` method, checks the return value for `value` and `done` (synchronous case), and handles the promise for the asynchronous case.
    * **`CloseSync`:** How it calls the `return()` method and handles potential exceptions.
    * **`CloseAsync`:**  How it calls the `return()` method, wraps the result in a promise, and uses a fulfillment function (`AsyncIteratorCloseFulfillFunction`).

5. **Identifying Relationships with HTML/CSS:** This requires a step back. Iterators in JavaScript are often used when dealing with collections of elements, processing data, or handling asynchronous operations. In the context of a browser engine, this naturally connects to the DOM (HTML elements) and potentially CSSOM (CSS objects). Examples would involve iterating over the children of a node, the results of a query selector, or even processing data fetched from a network request.

6. **Logical Reasoning and Examples:** This involves creating concrete scenarios to illustrate the functionality. For `FromIterable`, showing how different iterable objects are handled (arrays, custom iterators, async generators) is key. For `Next`, demonstrating the progression of values and the `done` flag is important. For `Close`, showing how `return()` is invoked and how errors are handled is useful.

7. **Common Usage Errors:**  Thinking about how developers might misuse iterators helps identify potential pitfalls. Forgetting to handle the `done` flag, assuming synchronous behavior for async iterators, or not properly closing iterators are common mistakes.

8. **Debugging Information:**  Understanding how a user's action could lead to this code being executed is crucial for debugging. This involves tracing the execution flow from a user interaction (like clicking a button or a page loading) to the JavaScript code that uses an iterator, and then down into the Blink engine's implementation.

9. **Structuring the Answer:**  Finally, organizing the information logically with clear headings and examples makes the answer easier to understand. Starting with the core functionality, then moving to JavaScript relationships, examples, errors, and debugging information provides a comprehensive overview.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "It's just about iterators."  **Refinement:** Realize the distinction between synchronous and asynchronous iterators and the significant role of Promises for the latter.
* **Initial thought:** "The examples are obvious." **Refinement:**  Make the examples more specific and illustrate different scenarios (e.g., a custom iterator vs. an array iterator).
* **Initial thought:** "Debugging info is just about breakpoints." **Refinement:** Think about the user's perspective – what actions would trigger the relevant JavaScript code and thus involve this C++ code?

By following this structured approach, combining code analysis with knowledge of JavaScript concepts and considering practical usage scenarios, a comprehensive and accurate explanation of the `script_iterator.cc` file can be generated.
好的，我们来分析一下 `blink/renderer/bindings/core/v8/script_iterator.cc` 这个文件。

**文件功能概述**

这个文件定义了 `ScriptIterator` 类，其主要功能是**在 Blink 渲染引擎中，为 JavaScript 的迭代器协议提供 C++ 的实现和支持**。  它充当了 JavaScript 迭代器对象和 Blink 内部 C++ 代码之间的桥梁。

更具体地说，`ScriptIterator` 负责：

1. **创建迭代器：** 从一个 JavaScript 可迭代对象（Iterable）中获取迭代器（Iterator）。
2. **推进迭代器：** 调用迭代器的 `next()` 方法来获取下一个迭代结果。
3. **关闭迭代器：** 调用迭代器的 `return()` 方法（如果存在）来执行清理操作并告知迭代已完成。这包括同步和异步迭代器的关闭。
4. **处理异步迭代器：** 特别处理 JavaScript 的异步迭代器，包括管理 Promise 和异步操作。
5. **错误处理：**  捕获并处理在迭代过程中可能发生的 JavaScript 异常。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`ScriptIterator` 直接与 JavaScript 的迭代器协议相关，而迭代器在 JavaScript 中被广泛用于处理集合数据、异步操作等。这间接地与 HTML 和 CSS 的某些功能相关联，因为 JavaScript 经常被用来操作 DOM（HTML 结构）和 CSSOM（CSS 样式）。

**1. 与 JavaScript 的关系：**

* **迭代器协议:** `ScriptIterator` 实现了 JavaScript 的迭代器协议，包括 `@@iterator` 和 `@@asyncIterator` Symbol，以及 `next()` 和 `return()` 方法。
    * **示例:**  当 JavaScript 代码中使用 `for...of` 循环遍历一个数组、Map、Set 或者自定义的可迭代对象时，Blink 引擎会调用 `ScriptIterator::FromIterable` 来获取迭代器。
    ```javascript
    const myArray = [1, 2, 3];
    for (const item of myArray) {
      console.log(item); // 这里的遍历过程会用到 ScriptIterator
    }

    async function* asyncGenerator() {
      yield 1;
      yield 2;
    }

    async function main() {
      for await (const item of asyncGenerator()) {
        console.log(item); // 这里用到处理异步迭代的 ScriptIterator
      }
    }
    ```

* **异步迭代器和 Promise:**  `ScriptIterator` 专门处理异步迭代器，它使用 Promise 来处理 `next()` 方法返回的异步结果，以及 `return()` 方法的异步关闭。
    * **示例:**  当使用 `for await...of` 循环遍历一个异步可迭代对象（如异步生成器）时，`ScriptIterator` 会管理返回的 Promise。

**2. 与 HTML 的关系：**

* **DOM 集合:**  HTML 元素的集合，如 `NodeList` (例如 `document.querySelectorAll()` 的结果) 和 `HTMLCollection`，通常是可迭代的。`ScriptIterator` 用于遍历这些集合。
    * **假设输入:**  JavaScript 代码执行 `document.querySelectorAll('div')` 返回一个包含多个 div 元素的 `NodeList`。
    * **输出:**  如果随后使用 `for...of` 循环遍历这个 `NodeList`，`ScriptIterator` 将被用来逐个访问这些 div 元素。

* **事件处理:** 某些事件相关的对象可能是可迭代的，例如某些类型的流。`ScriptIterator` 可以用于处理这些流。

**3. 与 CSS 的关系：**

* **CSSOM 集合:**  类似于 DOM，CSSOM 中也存在一些可迭代的集合，例如 `CSSRuleList` (例如 `document.styleSheets[0].cssRules`)。
    * **假设输入:** JavaScript 代码执行 `document.styleSheets[0].cssRules` 获取一个 `CSSRuleList`。
    * **输出:** 使用 `for...of` 遍历这个 `CSSRuleList` 时，`ScriptIterator` 会被调用来访问每个 CSS 规则。

**逻辑推理与假设输入/输出**

以 `ScriptIterator::FromIterable` 方法为例：

* **假设输入:** 一个 JavaScript 数组对象 `[10, 20, 30]` 被传递给 `FromIterable`。
* **逻辑推理:**
    1. `FromIterable` 会检查数组对象是否具有 `@@iterator` Symbol 属性。
    2. 由于数组是内置的可迭代对象，它会找到 `@@iterator` 方法。
    3. 调用 `@@iterator` 方法会返回一个迭代器对象。
    4. `FromIterable` 会创建一个 `ScriptIterator` 实例，其中包含了对迭代器对象和其 `next` 方法的引用。
* **输出:** 一个 `ScriptIterator` 对象，可以用于遍历数组中的元素。

以 `ScriptIterator::Next` 方法为例：

* **假设输入:**  一个已经创建好的 `ScriptIterator` 对象，用于遍历数组 `[10, 20, 30]`。
* **逻辑推理:**
    1. `Next` 方法会调用 JavaScript 迭代器对象的 `next()` 方法。
    2. 第一次调用 `next()` 会返回 `{ value: 10, done: false }`。
    3. 第二次调用 `next()` 会返回 `{ value: 20, done: false }`。
    4. 第三次调用 `next()` 会返回 `{ value: 30, done: false }`。
    5. 第四次调用 `next()` 会返回 `{ value: undefined, done: true }`。
* **输出:**  每次调用 `Next`，都会更新 `ScriptIterator` 的内部状态，并返回一个指示是否完成的布尔值。同时，可以通过 `value()` 方法获取当前的值。

**用户或编程常见的使用错误**

* **未处理 `done` 状态:** 开发者可能忘记检查迭代器返回的 `done` 属性，导致在迭代完成后继续尝试访问 `value`，这可能会导致未定义行为或错误。
    * **示例:**
    ```javascript
    const iterator = [1, 2].values();
    let result = iterator.next();
    console.log(result.value); // 1
    result = iterator.next();
    console.log(result.value); // 2
    result = iterator.next();
    console.log(result.value); // undefined (但应该检查 result.done)
    ```

* **在异步迭代中假设同步行为:**  对于异步迭代器，`next()` 方法返回的是一个 Promise。开发者可能会错误地假设它可以立即返回结果，而没有正确处理 Promise。
    * **示例:**
    ```javascript
    async function* asyncGenerator() {
      yield 1;
    }
    const iterator = asyncGenerator();
    const resultPromise = iterator.next();
    console.log(resultPromise.value); // 错误：resultPromise 是 Promise，没有 value 属性
    resultPromise.then(result => console.log(result.value)); // 正确处理方式
    ```

* **不正确地关闭迭代器:**  虽然 `return()` 方法是可选的，但对于某些需要清理资源的迭代器（例如读取文件流），不正确地关闭可能会导致资源泄漏。

**用户操作如何一步步到达这里 (调试线索)**

假设用户在网页上执行了以下操作：

1. **用户在浏览器中打开一个网页。**
2. **网页加载完成，包含一些 JavaScript 代码。**
3. **JavaScript 代码执行了以下操作：**
   ```javascript
   const divs = document.querySelectorAll('div');
   for (const div of divs) {
     console.log(div.textContent);
   }
   ```

**调试线索：**

1. **`document.querySelectorAll('div')` 执行:**  当 JavaScript 引擎执行这行代码时，Blink 渲染引擎会找到所有匹配的 div 元素并创建一个 `NodeList` 对象。`NodeList` 是一个可迭代对象。
2. **`for...of` 循环开始:**  当 JavaScript 引擎执行 `for...of` 循环时，它需要获取 `divs` 的迭代器。
3. **调用 `ScriptIterator::FromIterable`:**  Blink 的 JavaScript 绑定代码会调用 `ScriptIterator::FromIterable` 方法，并将 `divs` 对象传递给它。
    * **此时，`FromIterable` 的输入：** `v8::Local<v8::Object>` 代表 `NodeList` 对象。
4. **`FromIterable` 内部操作:**
   - 获取 `NodeList` 的 `@@iterator` 方法。
   - 调用 `@@iterator` 方法，返回一个迭代器对象。
   - 创建并返回一个 `ScriptIterator` 对象。
5. **循环的每次迭代:**
   - `for...of` 循环会调用 `ScriptIterator::Next` 方法来获取下一个 div 元素。
   - **此时，`Next` 的输入：**  之前创建的 `ScriptIterator` 对象。
   - `Next` 方法会调用 JavaScript 迭代器对象的 `next()` 方法，返回一个包含当前 div 元素的 `value` 和 `done` 状态的对象。
6. **循环继续直到结束:**  这个过程会重复，直到迭代器的 `done` 属性变为 `true`。

**在调试器中设置断点：**

为了调试与迭代器相关的问题，可以在以下位置设置断点：

* **`ScriptIterator::FromIterable`:**  查看如何从 JavaScript 对象创建 `ScriptIterator`。
* **`ScriptIterator::Next`:**  查看如何获取下一个迭代结果。
* **`ScriptIterator::CloseSync` 和 `ScriptIterator::CloseAsync`:** 查看迭代器如何关闭。

通过这些断点，开发者可以跟踪 JavaScript 代码中的迭代过程在 Blink 引擎中的具体实现，理解数据是如何被访问和处理的。

总而言之，`blink/renderer/bindings/core/v8/script_iterator.cc` 是 Blink 引擎中一个关键的文件，它负责实现 JavaScript 迭代器协议，使得 JavaScript 代码能够方便地遍历各种集合和处理异步数据流。 理解这个文件有助于深入了解 JavaScript 在浏览器中的运行机制。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/script_iterator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/bindings/core/v8/script_iterator.h"

#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_script_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_string_resource.h"
#include "third_party/blink/renderer/platform/bindings/exception_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"

namespace blink {

namespace {

class AsyncIteratorCloseFulfillFunction final
    : public ThenCallable<IDLAny, AsyncIteratorCloseFulfillFunction, IDLAny> {
 public:
  explicit AsyncIteratorCloseFulfillFunction(
      const ExceptionContext& exception_context) {
    SetExceptionContext(exception_context);
  }

  ScriptValue React(ScriptState* script_state, ScriptValue value) {
    // In a detached context, we shouldn't proceed to do things that can run
    // script.
    if (!script_state->ContextIsValid()) {
      return ScriptValue();
    }

    // 9.1. If Type(returnPromiseResult) is not Object, throw a TypeError.
    if (!value.V8Value()->IsObject()) {
      V8ThrowException::ThrowTypeError(
          script_state->GetIsolate(),
          "Expected return() to resolve to an Object.");
      return ScriptValue();
    }
    // 9.2. Return undefined.
    return ScriptValue();
  }

  void Trace(Visitor* visitor) const final {
    ThenCallable<IDLAny, AsyncIteratorCloseFulfillFunction, IDLAny>::Trace(
        visitor);
  }
};

}  // namespace

// static
ScriptIterator ScriptIterator::FromIterable(v8::Isolate* isolate,
                                            v8::Local<v8::Object> iterable,
                                            ExceptionState& exception_state,
                                            Kind kind) {
  // 7.4.3 GetIterator(obj, kind).
  // https://tc39.es/ecma262/#sec-getiterator
  TryRethrowScope rethrow_scope(isolate, exception_state);
  v8::Local<v8::Context> current_context = isolate->GetCurrentContext();

  v8::Local<v8::Value> method;

  // 1. If kind is ASYNC, then.
  if (kind == Kind::kAsync) {
    // 1.a. Let method be ? GetMethod(obj, @@asyncIterator).
    if (!iterable->Get(current_context, v8::Symbol::GetAsyncIterator(isolate))
             .ToLocal(&method)) {
      DCHECK(rethrow_scope.HasCaught());
      return ScriptIterator();
    }

    // 1.b. If method is undefined, then
    //
    // We use `IsNullOrUndefined()` here instead of `IsUndefined()`, because
    // ECMAScript's GetMethod() abstract operation returns undefined for methods
    // that are either null or undefined.
    // https://github.com/tc39/ecma262/issues/3417.
    if (method->IsNullOrUndefined()) {
      // TODO(crbug.com/356891478): Match ECMAScript by falling back to creating
      // an async iterator out of an @@iterable implementation, if such an
      // implementation exists:
      //
      // 1.b.i Let syncMethod be ? GetMethod(obj, %Symbol.iterator%).
      // 1.b.ii. If syncMethod is undefined, throw a TypeError exception.
      // 1.b.iii. Let syncIteratorRecord be ? GetIteratorFromMethod(obj,
      //          syncMethod).
      // 1.b.iv. Return CreateAsyncFromSyncIterator(syncIteratorRecord).
      //
      // For now, we just return an `IsNull()` iterator with no exception.
      DCHECK(!rethrow_scope.HasCaught());
      return ScriptIterator();
    }
  } else {
    // 2. Else, let method be ? GetMethod(obj, @@iterator).
    if (!iterable->Get(current_context, v8::Symbol::GetIterator(isolate))
             .ToLocal(&method)) {
      DCHECK(rethrow_scope.HasCaught());
      return ScriptIterator();
    }
    // 3. If method is undefined, throw a TypeError exception.
    //
    // Note we deviate from the spec here! Some algorithms in Web IDL want to
    // change their behavior when `method` is undefined, so give them a choice.
    // They can detect this case by seeing that `IsNull()` is true and there is
    // no exception on the stack.
    //
    // See documentation above about why we use `IsNullOrUndefined()` instead of
    // `IsUndefined()`.
    if (method->IsNullOrUndefined()) {
      DCHECK(!rethrow_scope.HasCaught());
      return ScriptIterator();
    }
  }

  // GetMethod(V, P):
  // https://tc39.es/ecma262/#sec-getmethod.
  //
  // 3. If IsCallable(func) is false, throw a TypeError exception.
  if (!method->IsFunction()) {
    if (kind == Kind::kAsync) {
      exception_state.ThrowTypeError("@@asyncIterator must be a callable.");
    } else {
      exception_state.ThrowTypeError("@@iterator must be a callable.");
    }
    return ScriptIterator();
  }

  // 4. Return ? GetIteratorFromMethod(obj, method).
  //
  // The rest of this algorithm quotes the GetIteratorFromMethod(obj, method)
  // abstract algorithm spec text:
  // https://tc39.es/ecma262/#sec-getiteratorfrommethod
  //
  // 1. Let iterator be ? Call(method, obj).
  v8::Local<v8::Value> iterator;
  if (!V8ScriptRunner::CallFunction(method.As<v8::Function>(),
                                    ToExecutionContext(current_context),
                                    iterable, 0, nullptr, isolate)
           .ToLocal(&iterator)) {
    DCHECK(rethrow_scope.HasCaught());
    return ScriptIterator();
  }

  // 2. If iterator is not Object, throw a TypeError exception.
  if (!iterator->IsObject()) {
    exception_state.ThrowTypeError("Iterator object must be an object.");
    return ScriptIterator();
  }

  // 3. Let nextMethod be ? Get(iterator, "next").
  v8::Local<v8::Value> next_method;
  if (!iterator.As<v8::Object>()
           ->Get(current_context, V8AtomicString(isolate, "next"))
           .ToLocal(&next_method)) {
    return ScriptIterator();
  }

  // 4. Let iteratorRecord be the Iterator Record { [[Iterator]]: iterator,
  //    [[NextMethod]]: nextMethod, [[Done]]: false }.
  // 5. Return iteratorRecord.
  return ScriptIterator(isolate, iterator.As<v8::Object>(), next_method, kind);
}

ScriptIterator::ScriptIterator(v8::Isolate* isolate,
                               v8::Local<v8::Object> iterator,
                               v8::Local<v8::Value> next_method,
                               Kind kind)
    : isolate_(isolate),
      iterator_(isolate, iterator),
      next_method_(isolate, next_method),
      done_key_(V8AtomicString(isolate, "done")),
      value_key_(V8AtomicString(isolate, "value")),
      done_(false),
      kind_(kind) {
  DCHECK(!IsNull());
}

bool ScriptIterator::Next(ExecutionContext* execution_context,
                          ExceptionState& exception_state) {
  DCHECK(!IsNull());

  ScriptState* script_state = ScriptState::ForCurrentRealm(isolate_);
  v8::Local<v8::Value> next_method = next_method_.Get(script_state);
  if (!next_method->IsFunction()) {
    exception_state.ThrowTypeError("Expected next() function on iterator.");
    done_ = true;
    return false;
  }

  TryRethrowScope rethrow_scope(isolate_, exception_state);
  v8::Local<v8::Value> next_return_value;
  if (!V8ScriptRunner::CallFunction(
           next_method.As<v8::Function>(), execution_context,
           iterator_.Get(script_state), 0, nullptr, isolate_)
           .ToLocal(&next_return_value)) {
    done_ = true;
    return false;
  }
  if (!next_return_value->IsObject()) {
    exception_state.ThrowTypeError(
        "Expected iterator.next() to return an Object.");
    done_ = true;
    return false;
  }
  v8::Local<v8::Object> next_return_value_object =
      next_return_value.As<v8::Object>();

  v8::Local<v8::Context> context = script_state->GetContext();
  if (kind_ == Kind::kAsync) {
    value_ = WorldSafeV8Reference(isolate_, next_return_value);
    // Unlike synchronous iterators, in the async case, we don't know whether
    // the iteration is "done" yet, since `value_` is NOT expected to be
    // directly an `IteratorResult` object, but rather a Promise that resolves
    // to one. See [1]. In that case, we'll return true here since we have no
    // indication that the iterator is exhausted yet.
    //
    // [1]: https://tc39.es/ecma262/#table-async-iterator-required.
    return true;
  } else {
    v8::MaybeLocal<v8::Value> maybe_value =
        next_return_value_object->Get(context, value_key_);
    value_ = WorldSafeV8Reference(
        isolate_, maybe_value.FromMaybe(v8::Local<v8::Value>()));
    if (maybe_value.IsEmpty()) {
      done_ = true;
      return false;
    }

    v8::Local<v8::Value> done;
    if (!next_return_value_object->Get(context, done_key_).ToLocal(&done)) {
      done_ = true;
      return false;
    }
    done_ = done->BooleanValue(isolate_);
    return !done_;
  }
}

ScriptValue ScriptIterator::CloseSync(ScriptState* script_state,
                                      ExceptionState& exception_state,
                                      v8::Local<v8::Value> reason) {
  DCHECK_EQ(kind_, Kind::kSync);
  DCHECK(!IsNull());

  v8::Local<v8::Context> current_context = script_state->GetContext();
  v8::Local<v8::Object> iterator = iterator_.Get(script_state);

  TryRethrowScope rethrow_scope(isolate_, exception_state);

  // 7.4.9 IteratorClose().
  //
  // 3. Let innerResult be Completion(GetMethod(iterator, "return")).
  v8::Local<v8::Value> return_method;
  if (!iterator->Get(current_context, V8AtomicString(isolate_, "return"))
           .ToLocal(&return_method)) {
    DCHECK(rethrow_scope.HasCaught());
    // 6. If innerResult is a throw completion, return ? innerResult.
    return ScriptValue();
  }

  // 7.3.10 GetMethod(V, P):
  //
  // 3. If IsCallable(func) is false, throw a TypeError exception.
  if (!return_method->IsFunction()) {
    exception_state.ThrowTypeError("return() function must be callable.");
    return ScriptValue();
  }

  // 4. If innerResult is a normal completion, then
  //   a. Let return be innerResult.[[Value]].
  //   b. If return is undefined, return ? completion.
  if (return_method->IsNullOrUndefined()) {
    return ScriptValue();
  }

  // 4.c. Set innerResult to Completion(Call(return, iterator)).
  v8::Local<v8::Value> return_value;
  if (!V8ScriptRunner::CallFunction(return_method.As<v8::Function>(),
                                    ExecutionContext::From(script_state),
                                    iterator, reason.IsEmpty() ? 0 : 1, &reason,
                                    isolate_)
           .ToLocal(&return_value)) {
    DCHECK(rethrow_scope.HasCaught());
    // 6. If innerResult is a throw completion, return ? innerResult.
    return ScriptValue();
  }

  // If innerResult.[[Value]] is not an Object, throw a TypeError exception.
  if (!return_value->IsObject()) {
    exception_state.ThrowTypeError("Expected return() to return an Object.");
    return ScriptValue();
  }

  // 8. Return ? completion.
  return ScriptValue(isolate_, reason);
}

ScriptPromise<IDLAny> ScriptIterator::CloseAsync(
    ScriptState* script_state,
    const ExceptionContext& exception_context,
    v8::Local<v8::Value> reason) {
  DCHECK_EQ(kind_, Kind::kAsync);
  DCHECK(!IsNull());

  v8::Local<v8::Context> current_context = script_state->GetContext();
  v8::Local<v8::Object> iterator = iterator_.Get(script_state);

  // To close an async iterator<T> |iterator|, with reason |reason|:
  // https://whatpr.org/webidl/1397.html#async-iterator-close.
  v8::TryCatch try_catch(script_state->GetIsolate());

  // 3. Let returnMethod be GetMethod(iteratorObj, "return").
  v8::Local<v8::Value> return_method;
  if (!iterator->Get(current_context, V8AtomicString(isolate_, "return"))
           .ToLocal(&return_method)) {
    // 4. If returnMethod is an abrupt completion, return a promise rejected
    // with returnMethod.[[Value]].
    DCHECK(try_catch.HasCaught());
    ScriptPromise<IDLAny> rejected_promise =
        ScriptPromise<IDLAny>::Reject(script_state, try_catch.Exception());
    try_catch.Reset();
    return rejected_promise;
  }

  // 7.3.10 GetMethod(V, P):
  //
  // 3. If IsCallable(func) is false, throw a TypeError exception.
  if (!return_method->IsFunction()) {
    V8ThrowException::CreateTypeError(script_state->GetIsolate(),
                                      "return() function must be callable");
    ScriptPromise<IDLAny> rejected_promise =
        ScriptPromise<IDLAny>::Reject(script_state, try_catch.Exception());
    try_catch.Reset();
    return rejected_promise;
  }

  // 5. If returnMethod is undefined, return a promise resolved with
  //    undefined.
  if (return_method->IsNullOrUndefined()) {
    return EmptyPromise();
  }

  // 6. Let returnResult be
  //    Call(returnMethod.[[Value]], iteratorObj, « reason »).
  v8::Local<v8::Value> return_result;
  if (!V8ScriptRunner::CallFunction(return_method.As<v8::Function>(),
                                    ExecutionContext::From(script_state),
                                    iterator, reason.IsEmpty() ? 0 : 1, &reason,
                                    isolate_)
           .ToLocal(&return_result)) {
    // 7. If returnResult is an abrupt completion, return a promise rejected
    //    with returnResult.[[Value]].
    DCHECK(try_catch.HasCaught());
    ScriptPromise<IDLAny> rejected_promise =
        ScriptPromise<IDLAny>::Reject(script_state, try_catch.Exception());
    try_catch.Reset();
    return rejected_promise;
  }

  // 8. Let returnPromise be a promise resolved with returnResult.[[Value]].
  ScriptPromise<IDLAny> return_promise =
      ToResolvedPromise<IDLAny>(script_state, return_result);

  // 9. Return the result of reacting to returnPromise with the following
  //    fulfillment steps, given returnPromiseResult:
  //
  // (See documentation in `AsyncIteratorCloseFulfillFunction` for remaining
  // documentation).
  auto* on_fulfilled = MakeGarbageCollected<AsyncIteratorCloseFulfillFunction>(
      exception_context);
  return return_promise.Then(script_state, on_fulfilled);
}

}  // namespace blink
```