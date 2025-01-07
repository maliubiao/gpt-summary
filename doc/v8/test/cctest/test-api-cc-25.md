Response:
The user wants to understand the functionality of a V8 source code file: `v8/test/cctest/test-api.cc`. The prompt asks for:

1. **General functionality:** What does this code do?
2. **Torque source:** Is it a Torque file (ends with `.tq`)?
3. **JavaScript relation:** Does it relate to JavaScript functionality? If so, provide a JavaScript example.
4. **Code logic reasoning:**  Provide examples with input and output if there's logic to follow.
5. **Common programming errors:** Illustrate common errors this code helps test.
6. **Summary:** Provide a concise overview of the code's purpose.
7. **Part information:**  Acknowledge that this is part 26 of 36.

**Mental Process:**

1. **Filename analysis:** The path `v8/test/cctest/` suggests this file contains C++ tests for the V8 API. The `test-api.cc` name strongly indicates it's testing various aspects of the V8 C++ API.

2. **Code inspection:**  I'll skim through the provided code snippets, looking for patterns and keywords related to V8 API usage and testing. I see:
    * `TEST(...)`:  This is a common pattern for defining unit tests.
    * `LocalContext`, `v8::Isolate`, `v8::HandleScope`: These are fundamental V8 C++ API components for setting up a V8 environment.
    * `v8_num`, `v8_str`: Helper functions likely used to create V8 number and string objects.
    * `v8::PropertyDescriptor`:  Relates to defining properties on JavaScript objects.
    * `v8::Promise`, `v8::Promise::Resolver`: Deals with JavaScript Promise functionality.
    * `CompileRun(...)`:  A helper function to execute JavaScript code within the test environment.
    * `v8::Isolate::DisallowJavascriptExecutionScope`, `v8::Isolate::AllowJavascriptExecutionScope`:  Features for controlling JavaScript execution.
    * `v8::ScriptOrigin`, `v8::ScriptCompiler`: APIs related to compiling and managing JavaScript scripts.
    * `CHECK(...)`, `CHECK_EQ(...)`: Assertion macros used for verifying test outcomes.

3. **Torque check:** The filename ends with `.cc`, not `.tq`. So, it's not a Torque source file.

4. **JavaScript relation:** The presence of `CompileRun`, `v8::Promise`, `v8::PropertyDescriptor`, and the testing of script compilation clearly indicates a strong relationship with JavaScript functionality. I can construct JavaScript examples that relate to these tested API features.

5. **Code logic reasoning:** The tests largely follow a pattern of setting up a scenario, performing actions using the V8 API, and then using `CHECK` macros to verify the expected outcomes. I can describe this with examples, highlighting the setup, actions, and assertions.

6. **Common programming errors:** The tests implicitly cover common errors by verifying correct API usage. For example, the promise tests ensure the correct behavior of `then` and `catch`. The property descriptor tests verify correct construction of property attributes. I can elaborate on potential errors a user might make when using these APIs.

7. **Summary:** The file's purpose is to test the correctness and functionality of various parts of the V8 C++ API.

8. **Part information:** Acknowledge the given part number (26/36).

**Pre-computation/Pre-analysis (Internal):**

* **Histogram Scopes:** The initial part of the code with `NestedTimedHistogramScope` seems to be testing the logging and timing of events within V8. The nested structure and `PauseNestedTimedHistogramScope` likely test how these scopes interact. The `last_event_message` and `last_event_status` variables suggest tracking the last logged event.
* **Property Descriptors:** This section tests creating and manipulating `v8::PropertyDescriptor` objects, which are used to define the characteristics (value, writable, enumerable, configurable, getter, setter) of properties on JavaScript objects.
* **Promises:** The promise tests cover creation, resolution, rejection, and chaining using `then` and `catch`. The microtask policy setting is also relevant.
* **JavaScript Execution Control:** The `DisallowJavascriptExecutionScope` and `AllowJavascriptExecutionScope` tests verify the mechanism for preventing or allowing JavaScript execution in specific code sections.
* **Script Information:** The `ScriptNameAndLineNumber` and `ScriptPositionInfo` tests examine how V8 tracks the source location information (URL, line number, column) of scripts. The different variations of `GetPositionInfo` with and without offset, and with pre-computed line ends are important details.
* **Magic Comments:** The final part tests how V8 parses and handles special comments (`//# sourceURL=`, `//# sourceMappingURL=`) in JavaScript code.

By following these steps and inspecting the code, I can systematically address all parts of the user's request.
这是 V8 引擎源代码 `v8/test/cctest/test-api.cc` 的一部分，它是一个 C++ 文件，包含了一系列用于测试 V8 C++ API 功能的单元测试。

**功能列举:**

从提供的代码片段来看，这个文件中的测试主要关注以下 V8 API 的功能：

1. **事件记录和性能分析 (Histogram Scopes):**  测试了 V8 中用于记录事件和测量时间间隔的 API，例如 `i::NestedTimedHistogramScope` 和 `i::PauseNestedTimedHistogramScope`。这些用于性能分析和监控。它检查了事件的开始和结束状态，以及事件消息是否正确。

2. **属性描述符 (PropertyDescriptor):** 测试了 `v8::PropertyDescriptor` 类的功能，该类用于定义 JavaScript 对象属性的各种特性，如值、可写性、可枚举性、可配置性、getter 和 setter。测试用例涵盖了创建不同类型的属性描述符，包括数据描述符和访问器描述符。

3. **Promise:** 测试了 JavaScript Promise 相关的 API，包括 Promise 的创建、解析 (resolve)、拒绝 (reject)、状态检查 (`IsPromise`) 以及链式调用 (`then` 和 `catch`)。

4. **JavaScript 执行控制 (Disallow/AllowJavascriptExecutionScope):** 测试了控制 JavaScript 代码执行的 API，例如 `v8::Isolate::DisallowJavascriptExecutionScope` 和 `v8::Isolate::AllowJavascriptExecutionScope`。这些用于在某些特定场景下阻止或允许 JavaScript 代码的执行。

5. **脚本信息 (ScriptNameAndLineNumber, ScriptPositionInfo):** 测试了获取脚本相关信息的 API，例如脚本的名称 (URL) 和行号，以及在脚本中特定位置的详细信息（行号、列号、行起始和结束位置）。

6. **SourceURL 和 SourceMappingURL (Magic Comments):** 测试了 V8 如何处理 JavaScript 代码中的特殊注释 `//# sourceURL=` 和 `//# sourceMappingURL=`，用于指定脚本的源 URL 和 Source Map URL。

**是否为 Torque 源代码:**

根据您的描述，`v8/test/cctest/test-api.cc` 以 `.cc` 结尾，而不是 `.tq`。因此，**它不是一个 V8 Torque 源代码文件**，而是一个标准的 C++ 源代码文件。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个文件中的测试直接针对 V8 引擎提供的 JavaScript 功能的 C++ API 进行测试。以下是一些与提供的 C++ 代码相关的 JavaScript 示例：

* **属性描述符:**

```javascript
const obj = {};

// 使用 Object.defineProperty 定义属性，其行为类似于 v8::PropertyDescriptor
Object.defineProperty(obj, 'myProperty', {
  value: 42,
  writable: false,
  enumerable: false,
  configurable: false
});

console.log(obj.myProperty); // 输出 42
obj.myProperty = 100; // 严格模式下会报错，非严格模式下赋值无效
console.log(obj.myProperty); // 仍然输出 42

for (let key in obj) {
  console.log(key); // 不会输出 'myProperty' 因为 enumerable 为 false
}

delete obj.myProperty; // 删除失败，因为 configurable 为 false
console.log(obj.myProperty); // 仍然输出 42

let getterCalled = false;
let setterCalled = false;
Object.defineProperty(obj, 'accessorProperty', {
  get: function() {
    getterCalled = true;
    return 'getter value';
  },
  set: function(newValue) {
    setterCalled = true;
  }
});

console.log(obj.accessorProperty); // 输出 'getter value', getterCalled 为 true
obj.accessorProperty = 'new value'; // setterCalled 为 true
```

* **Promise:**

```javascript
const promise = new Promise((resolve, reject) => {
  // 模拟异步操作
  setTimeout(() => {
    const success = true; // 假设操作成功
    if (success) {
      resolve('操作成功！');
    } else {
      reject('操作失败！');
    }
  }, 1000);
});

promise.then((result) => {
  console.log('已完成:', result);
}).catch((error) => {
  console.error('已拒绝:', error);
});

console.log('Promise 创建后...');
```

* **SourceURL:**

```javascript
//# sourceURL=my-script.js
console.log('This is my script.');
```

当这段代码被执行时，例如在浏览器的开发者工具中，或者在 Node.js 中使用特定的方式加载，错误信息和调试信息可能会将这个脚本标记为 `my-script.js`，即使它没有实际存储在名为 `my-script.js` 的文件中。

**代码逻辑推理 (Histogram Scopes 测试):**

**假设输入:**  `histogram` 是一个已经创建的直方图对象，用于记录名为 "V8.Test" 的事件的耗时。`last_event_message` 和 `last_event_status` 是全局变量，用于跟踪最后记录的事件的消息和状态。`event_count` 是一个全局计数器，记录事件的数量。

**代码逻辑:**

这段代码通过嵌套的 `i::NestedTimedHistogramScope` 对象来模拟事件的嵌套发生和暂停。

1. **外层 scope0:**  创建一个名为 "V8.Test" 的事件，状态为 `kStart`，`event_count` 递增。
2. **内层 scope1:** 创建另一个 "V8.Test" 事件，状态为 `kStart`，`event_count` 递增。
3. **更内层 scope2:** 创建又一个 "V8.Test" 事件，状态为 `kStart`，`event_count` 递增。
4. **scope3:** 创建一个事件，`event_count` 递增。
5. **scope4 (Pause):**  暂停了 scope3 对应的事件的计时，但**不会**发出新的事件记录，因此 `event_count` 不变。
6. **scope5 和 scope5_1:**  创建两个嵌套的 "V8.Test" 事件，状态为 `kStart`，`event_count` 递增两次。
7. **scope5 结束后:**  scope5 的 "V8.Test" 事件结束，状态为 `kEnd`，`event_count` 递增。
8. **scope2 结束后:** scope2 的 "V8.Test" 事件结束，状态为 `kEnd`，`event_count` 递增。
9. **scope6 (Pause):** 暂停了 scope1 对应的事件的计时，`event_count` 不变。
10. **scope7 (Pause):** 在 scope6 暂停期间创建一个新的暂停 scope，`event_count` 不变。
11. **scope1 结束后:** scope1 的 "V8.Test" 事件结束，状态为 `kEnd`，`event_count` 递增。
12. **外层 scope0 结束后:** scope0 的 "V8.Test" 事件结束，状态为 `kEnd`，`event_count` 递增。

**预期输出:**  一系列的 `CHECK_EQ` 断言会验证在每个阶段 `last_event_message`、`last_event_status` 和 `event_count` 的值是否符合预期。关键在于理解 `PauseNestedTimedHistogramScope` 会暂停计时但不会立即触发事件结束的记录。

**用户常见的编程错误示例:**

* **Promise 的 `then` 和 `catch` 使用不当:**

```javascript
const myAsyncFunction = () => {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      const shouldFail = Math.random() < 0.5;
      if (shouldFail) {
        reject('Something went wrong!');
      } else {
        resolve('Operation successful.');
      }
    }, 500);
  });
};

myAsyncFunction().then(result => {
  console.log('Result:', result);
});
// 错误：缺少 catch 处理拒绝的情况
```

在这个例子中，如果 `myAsyncFunction` 的 Promise 被拒绝 (reject)，则没有 `catch` 语句来处理错误，这可能导致未处理的 Promise 拒绝错误。正确的做法是添加 `.catch()`：

```javascript
myAsyncFunction().then(result => {
  console.log('Result:', result);
}).catch(error => {
  console.error('Error:', error);
});
```

* **对属性描述符的理解不足，导致属性行为不符合预期:**

```javascript
const obj = {};
Object.defineProperty(obj, 'myProp', { value: 10 });

obj.myProp = 20; // 赋值操作看起来有效，但实际上可能没有改变值
console.log(obj.myProp); // 输出仍然是 10，因为 writable 默认为 false

Object.defineProperty(obj, 'myProp', { writable: true }); // 需要显式设置为 true
obj.myProp = 20;
console.log(obj.myProp); // 现在输出 20
```

开发者可能没有意识到 `Object.defineProperty` 创建的属性默认是不可写的，导致对属性的赋值操作没有效果。

**第 26 部分，共 36 部分的功能归纳:**

作为 `v8/test/cctest/test-api.cc` 的一部分，这段代码主要用于**测试 V8 引擎 C++ API 中关于事件记录、属性描述符、Promise、JavaScript 执行控制以及脚本信息处理等核心功能的正确性和稳定性**。它通过编写各种测试用例，模拟不同的使用场景，并使用断言来验证 API 的行为是否符合预期。这有助于确保 V8 引擎的这些关键功能能够可靠地运行。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第26部分，共36部分，请归纳一下它的功能

"""
vent_count);
      i::NestedTimedHistogramScope scope0(&histogram);
      CHECK_EQ(0, strcmp("V8.Test", last_event_message));
      CHECK_EQ(v8::LogEventStatus::kStart, last_event_status);
      CHECK_EQ(++count, event_count);
    }
    CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
    CHECK_EQ(++count, event_count);

    i::NestedTimedHistogramScope scope1(&histogram);
    CHECK_EQ(0, strcmp("V8.Test", last_event_message));
    CHECK_EQ(v8::LogEventStatus::kStart, last_event_status);
    CHECK_EQ(++count, event_count);
    {
      CHECK_EQ(count, event_count);
      i::NestedTimedHistogramScope scope2(&histogram);
      CHECK_EQ(0, strcmp("V8.Test", last_event_message));
      CHECK_EQ(v8::LogEventStatus::kStart, last_event_status);
      CHECK_EQ(++count, event_count);
      {
        CHECK_EQ(count, event_count);
        i::NestedTimedHistogramScope scope3(&histogram);
        CHECK_EQ(++count, event_count);
        i::PauseNestedTimedHistogramScope scope4(&histogram);
        // The outer timer scope is just paused, no event is emited yet.
        CHECK_EQ(count, event_count);
        {
          CHECK_EQ(count, event_count);
          i::NestedTimedHistogramScope scope5(&histogram);
          i::NestedTimedHistogramScope scope5_1(&histogram);
          CHECK_EQ(0, strcmp("V8.Test", last_event_message));
          CHECK_EQ(v8::LogEventStatus::kStart, last_event_status);
          count++;
          CHECK_EQ(++count, event_count);
        }
        CHECK_EQ(0, strcmp("V8.Test", last_event_message));
        CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
        count++;
        CHECK_EQ(++count, event_count);
      }
      CHECK_EQ(0, strcmp("V8.Test", last_event_message));
      CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
      CHECK_EQ(++count, event_count);
      i::PauseNestedTimedHistogramScope scope6(&histogram);
      // The outer timer scope is just paused, no event is emited yet.
      CHECK_EQ(count, event_count);
      {
        i::PauseNestedTimedHistogramScope scope7(&histogram);
        CHECK_EQ(count, event_count);
      }
      CHECK_EQ(count, event_count);
    }
    CHECK_EQ(0, strcmp("V8.Test", last_event_message));
    CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
    CHECK_EQ(++count, event_count);
    }
  CHECK_EQ(0, strcmp("V8.Test", last_event_message));
  CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
  CHECK_EQ(++count, event_count);
}

TEST(PropertyDescriptor) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  {  // empty descriptor
    v8::PropertyDescriptor desc;
    CHECK(!desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_configurable());
    CHECK(!desc.has_writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8_num(42));
    desc.set_enumerable(false);
    CHECK(desc.value() == v8_num(42));
    CHECK(desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(desc.has_enumerable());
    CHECK(!desc.enumerable());
    CHECK(!desc.has_configurable());
    CHECK(!desc.has_writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8_num(42));
    desc.set_configurable(true);
    CHECK(desc.value() == v8_num(42));
    CHECK(desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(desc.has_configurable());
    CHECK(desc.configurable());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8_num(42));
    desc.set_configurable(false);
    CHECK(desc.value() == v8_num(42));
    CHECK(desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(desc.has_configurable());
    CHECK(!desc.configurable());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8_num(42), false);
    CHECK(desc.value() == v8_num(42));
    CHECK(desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_configurable());
    CHECK(desc.has_writable());
    CHECK(!desc.writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8::Local<v8::Value>(), true);
    CHECK(!desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_configurable());
    CHECK(desc.has_writable());
    CHECK(desc.writable());
  }
  {
    // accessor descriptor
    CompileRun("var set = function() {return 43;};");

    v8::Local<v8::Function> set =
        v8::Local<v8::Function>::Cast(context->Global()
                                          ->Get(context.local(), v8_str("set"))
                                          .ToLocalChecked());
    v8::PropertyDescriptor desc(v8::Undefined(isolate), set);
    desc.set_configurable(false);
    CHECK(!desc.has_value());
    CHECK(desc.has_get());
    CHECK(desc.get() == v8::Undefined(isolate));
    CHECK(desc.has_set());
    CHECK(desc.set() == set);
    CHECK(!desc.has_enumerable());
    CHECK(desc.has_configurable());
    CHECK(!desc.configurable());
    CHECK(!desc.has_writable());
  }
  {
    // accessor descriptor with Proxy
    CompileRun(
        "var set = new Proxy(function() {}, {});"
        "var get = undefined;");

    v8::Local<v8::Value> get =
        v8::Local<v8::Value>::Cast(context->Global()
                                       ->Get(context.local(), v8_str("get"))
                                       .ToLocalChecked());
    v8::Local<v8::Function> set =
        v8::Local<v8::Function>::Cast(context->Global()
                                          ->Get(context.local(), v8_str("set"))
                                          .ToLocalChecked());
    v8::PropertyDescriptor desc(get, set);
    desc.set_configurable(false);
    CHECK(!desc.has_value());
    CHECK(desc.get() == v8::Undefined(isolate));
    CHECK(desc.has_get());
    CHECK(desc.set() == set);
    CHECK(desc.has_set());
    CHECK(!desc.has_enumerable());
    CHECK(desc.has_configurable());
    CHECK(!desc.configurable());
    CHECK(!desc.has_writable());
  }
  {
    // accessor descriptor with empty function handle
    v8::Local<v8::Function> get = v8::Local<v8::Function>();
    v8::PropertyDescriptor desc(get, get);
    CHECK(!desc.has_value());
    CHECK(!desc.has_get());
    CHECK(!desc.has_set());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_configurable());
    CHECK(!desc.has_writable());
  }
}

TEST(Promises) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Creation.
  Local<v8::Promise::Resolver> pr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise::Resolver> rr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise> p = pr->GetPromise();
  Local<v8::Promise> r = rr->GetPromise();

  // IsPromise predicate.
  CHECK(p->IsPromise());
  CHECK(r->IsPromise());
  Local<Value> o = v8::Object::New(isolate);
  CHECK(!o->IsPromise());

  // Resolution and rejection.
  pr->Resolve(context.local(), v8::Integer::New(isolate, 1)).FromJust();
  CHECK(p->IsPromise());
  rr->Reject(context.local(), v8::Integer::New(isolate, 2)).FromJust();
  CHECK(r->IsPromise());
}

// Promise.Then(on_fulfilled)
TEST(PromiseThen) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kExplicit);
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  // Creation.
  Local<v8::Promise::Resolver> pr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise::Resolver> qr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise> p = pr->GetPromise();
  Local<v8::Promise> q = qr->GetPromise();

  CHECK(p->IsPromise());
  CHECK(q->IsPromise());

  pr->Resolve(context.local(), v8::Integer::New(isolate, 1)).FromJust();
  qr->Resolve(context.local(), p).FromJust();

  // Chaining non-pending promises.
  CompileRun(
      "var x1 = 0;\n"
      "var x2 = 0;\n"
      "function f1(x) { x1 = x; return x+1 };\n"
      "function f2(x) { x2 = x; return x+1 };\n");
  Local<Function> f1 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f1")).ToLocalChecked());
  Local<Function> f2 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f2")).ToLocalChecked());

  // Then
  CompileRun("x1 = x2 = 0;");
  q->Then(context.local(), f1).ToLocalChecked();
  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  // Then
  CompileRun("x1 = x2 = 0;");
  pr = v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  qr = v8::Promise::Resolver::New(context.local()).ToLocalChecked();

  qr->Resolve(context.local(), pr).FromJust();
  qr->GetPromise()
      ->Then(context.local(), f1)
      .ToLocalChecked()
      ->Then(context.local(), f2)
      .ToLocalChecked();

  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  pr->Resolve(context.local(), v8::Integer::New(isolate, 3)).FromJust();

  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(3, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(4, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
}

// Promise.Then(on_fulfilled, on_rejected)
TEST(PromiseThen2) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kExplicit);
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  // Creation.
  Local<v8::Promise::Resolver> pr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise> p = pr->GetPromise();

  CHECK(p->IsPromise());

  pr->Resolve(context.local(), v8::Integer::New(isolate, 1)).FromJust();

  // Chaining non-pending promises.
  CompileRun(
      "var x1 = 0;\n"
      "var x2 = 0;\n"
      "function f1(x) { x1 = x; return x+1 };\n"
      "function f2(x) { x2 = x; return x+1 };\n"
      "function f3(x) { throw x + 100 };\n");
  Local<Function> f1 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f1")).ToLocalChecked());
  Local<Function> f2 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f2")).ToLocalChecked());
  Local<Function> f3 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f3")).ToLocalChecked());

  // Then
  CompileRun("x1 = x2 = 0;");
  Local<v8::Promise> a = p->Then(context.local(), f1, f2).ToLocalChecked();
  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  Local<v8::Promise> b = a->Then(context.local(), f3, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  Local<v8::Promise> c = b->Then(context.local(), f1, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(102, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());

  v8::Local<v8::Promise> d = c->Then(context.local(), f1, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(103, global->Get(context.local(), v8_str("x1"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  CHECK_EQ(102, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());

  v8::Local<v8::Promise> e = d->Then(context.local(), f3, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(103, global->Get(context.local(), v8_str("x1"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  CHECK_EQ(102, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());

  v8::Local<v8::Promise> f = e->Then(context.local(), f1, f3).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(103, global->Get(context.local(), v8_str("x1"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  CHECK_EQ(102, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());

  f->Then(context.local(), f1, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(103, global->Get(context.local(), v8_str("x1"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  CHECK_EQ(304, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
}

TEST(PromiseCatchCallsBuiltin) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  v8::Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  v8::Local<v8::Promise> promise = resolver->GetPromise();

  resolver->Reject(context.local(), v8::Integer::New(isolate, 1)).FromJust();

  CompileRun(
      "var x1 = 0;\n"
      "function f(x) { x1 = x; }\n"
      "Promise.prototype.then = function () { throw 'unreachable'; };\n");
  Local<Function> f = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f")).ToLocalChecked());

  // Catch should not call monkey-patched Promise.prototype.then.
  promise->Catch(context.local(), f).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
}

TEST(PromiseStateAndValue) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "var resolver;"
      "new Promise((res, rej) => { resolver = res; })");
  v8::Local<v8::Promise> promise = v8::Local<v8::Promise>::Cast(result);
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kPending);

  CompileRun("resolver('fulfilled')");
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kFulfilled);
  CHECK(v8_str("fulfilled")->SameValue(promise->Result()));

  result = CompileRun("Promise.reject('rejected')");
  promise = v8::Local<v8::Promise>::Cast(result);
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
  CHECK(v8_str("rejected")->SameValue(promise->Result()));
}

TEST(ResolvedPromiseReFulfill) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> value1 = v8::String::NewFromUtf8Literal(isolate, "foo");
  v8::Local<v8::String> value2 = v8::String::NewFromUtf8Literal(isolate, "bar");

  v8::Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  v8::Local<v8::Promise> promise = resolver->GetPromise();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kPending);

  resolver->Resolve(context.local(), value1).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kFulfilled);
  CHECK_EQ(promise->Result(), value1);

  // This should be a no-op.
  resolver->Resolve(context.local(), value2).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kFulfilled);
  CHECK_EQ(promise->Result(), value1);

  // This should be a no-op.
  resolver->Reject(context.local(), value2).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kFulfilled);
  CHECK_EQ(promise->Result(), value1);
}

TEST(RejectedPromiseReFulfill) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> value1 = v8::String::NewFromUtf8Literal(isolate, "foo");
  v8::Local<v8::String> value2 = v8::String::NewFromUtf8Literal(isolate, "bar");

  v8::Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  v8::Local<v8::Promise> promise = resolver->GetPromise();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kPending);

  resolver->Reject(context.local(), value1).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
  CHECK_EQ(promise->Result(), value1);

  // This should be a no-op.
  resolver->Reject(context.local(), value2).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
  CHECK_EQ(promise->Result(), value1);

  // This should be a no-op.
  resolver->Resolve(context.local(), value2).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
  CHECK_EQ(promise->Result(), value1);
}

TEST(DisallowJavascriptExecutionScope) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Isolate::DisallowJavascriptExecutionScope no_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::CRASH_ON_FAILURE);
  CompileRun("2+2");
}

TEST(AllowJavascriptExecutionScope) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Isolate::DisallowJavascriptExecutionScope no_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::CRASH_ON_FAILURE);
  v8::Isolate::DisallowJavascriptExecutionScope throw_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::THROW_ON_FAILURE);
  { v8::Isolate::AllowJavascriptExecutionScope yes_js(isolate);
    CompileRun("1+1");
  }
}

TEST(ThrowOnJavascriptExecution) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  v8::Isolate::DisallowJavascriptExecutionScope throw_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::THROW_ON_FAILURE);
  CompileRun("1+1");
  CHECK(try_catch.HasCaught());
}

namespace {

class MockPlatform final : public TestPlatform {
 public:
  bool dump_without_crashing_called() const {
    return dump_without_crashing_called_;
  }

  void DumpWithoutCrashing() override { dump_without_crashing_called_ = true; }

 private:
  bool dump_without_crashing_called_ = false;
};

}  // namespace

TEST_WITH_PLATFORM(DumpOnJavascriptExecution, MockPlatform) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Isolate::DisallowJavascriptExecutionScope throw_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::DUMP_ON_FAILURE);
  CHECK(!platform.dump_without_crashing_called());
  CompileRun("1+1");
  CHECK(platform.dump_without_crashing_called());
}

TEST(Regress354123) {
  LocalContext current;
  v8::Isolate* isolate = current->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessCounter);
  CHECK(current->Global()
            ->Set(current.local(), v8_str("friend"),
                  templ->NewInstance(current.local()).ToLocalChecked())
            .FromJust());

  // Test access using __proto__ from the prototype chain.
  access_count = 0;
  CompileRun("friend.__proto__ = {};");
  CHECK_EQ(2, access_count);
  CompileRun("friend.__proto__;");
  CHECK_EQ(4, access_count);

  // Test access using __proto__ as a hijacked function (A).
  access_count = 0;
  CompileRun("var p = Object.prototype;"
             "var f = Object.getOwnPropertyDescriptor(p, '__proto__').set;"
             "f.call(friend, {});");
  CHECK_EQ(1, access_count);
  CompileRun("var p = Object.prototype;"
             "var f = Object.getOwnPropertyDescriptor(p, '__proto__').get;"
             "f.call(friend);");
  CHECK_EQ(2, access_count);

  // Test access using __proto__ as a hijacked function (B).
  access_count = 0;
  CompileRun("var f = Object.prototype.__lookupSetter__('__proto__');"
             "f.call(friend, {});");
  CHECK_EQ(1, access_count);
  CompileRun("var f = Object.prototype.__lookupGetter__('__proto__');"
             "f.call(friend);");
  CHECK_EQ(2, access_count);

  // Test access using Object.setPrototypeOf reflective method.
  access_count = 0;
  CompileRun("Object.setPrototypeOf(friend, {});");
  CHECK_EQ(1, access_count);
  CompileRun("Object.getPrototypeOf(friend);");
  CHECK_EQ(2, access_count);
}


namespace {
bool ValueEqualsString(v8::Isolate* isolate, Local<Value> lhs,
                       const char* rhs) {
  CHECK(!lhs.IsEmpty());
  CHECK(lhs->IsString());
  String::Utf8Value utf8_lhs(isolate, lhs);
  return strcmp(rhs, *utf8_lhs) == 0;
}
}  // namespace

TEST(ScriptNameAndLineNumber) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(v8_str(url), 13, 0);
  v8::ScriptCompiler::Source script_source(v8_str("var foo;"), origin);

  Local<Script> script =
      v8::ScriptCompiler::Compile(env.local(), &script_source).ToLocalChecked();
  CHECK(ValueEqualsString(isolate, script->GetUnboundScript()->GetScriptName(),
                          url));

  int line_number = script->GetUnboundScript()->GetLineNumber(0);
  CHECK_EQ(13, line_number);
}

TEST(ScriptPositionInfo) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(v8_str(url), 13, 0);
  v8::ScriptCompiler::Source script_source(v8_str("var foo;\n"
                                                  "var bar;\n"
                                                  "var fisk = foo + bar;\n"),
                                           origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(env.local(), &script_source).ToLocalChecked();

  i::DirectHandle<i::SharedFunctionInfo> obj = i::Cast<i::SharedFunctionInfo>(
      v8::Utils::OpenDirectHandle(*script->GetUnboundScript()));
  CHECK(IsScript(obj->script()));

  i::DirectHandle<i::Script> script1(i::Cast<i::Script>(obj->script()),
                                     i_isolate);

  i::Script::PositionInfo info;

  for (int i = 0; i < 2; ++i) {
    // With offset.

    // Behave as if 0 was passed if position is negative.
    CHECK(script1->GetPositionInfo(-1, &info));
    CHECK_EQ(13, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(0, &info));
    CHECK_EQ(13, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(8, &info));
    CHECK_EQ(13, info.line);
    CHECK_EQ(8, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(9, &info));
    CHECK_EQ(14, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(9, info.line_start);
    CHECK_EQ(17, info.line_end);

    // Fail when position is larger than script size.
    CHECK(!script1->GetPositionInfo(220384, &info));

    // Without offset.

    // Behave as if 0 was passed if position is negative.
    CHECK(
        script1->GetPositionInfo(-1, &info, i::Script::OffsetFlag::kNoOffset));
    CHECK_EQ(0, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(0, &info, i::Script::OffsetFlag::kNoOffset));
    CHECK_EQ(0, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(8, &info, i::Script::OffsetFlag::kNoOffset));
    CHECK_EQ(0, info.line);
    CHECK_EQ(8, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(9, &info, i::Script::OffsetFlag::kNoOffset));
    CHECK_EQ(1, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(9, info.line_start);
    CHECK_EQ(17, info.line_end);

    // Fail when position is larger than script size.
    CHECK(!script1->GetPositionInfo(220384, &info,
                                    i::Script::OffsetFlag::kNoOffset));

    i::Script::InitLineEnds(i_isolate, script1);
  }
}

TEST(ScriptPositionInfoWithLineEnds) {
  // Same as ScriptPositionInfo, but using out-of-heap cached line ends
  // information. In this case we do not need the two passes (with heap cached)
  // line information and without it that were required in ScriptPositionInfo.
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(v8_str(url), 13, 0);
  v8::ScriptCompiler::Source script_source(v8_str("var foo;\n"
                                                  "var bar;\n"
                                                  "var fisk = foo + bar;\n"),
                                           origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(env.local(), &script_source).ToLocalChecked();

  i::DirectHandle<i::SharedFunctionInfo> obj = i::Cast<i::SharedFunctionInfo>(
      v8::Utils::OpenDirectHandle(*script->GetUnboundScript()));
  CHECK(IsScript(obj->script()));

  i::DirectHandle<i::Script> script1(i::Cast<i::Script>(obj->script()),
                                     i_isolate);

  i::String::LineEndsVector line_ends =
      i::Script::GetLineEnds(i_isolate, script1);

  i::Script::PositionInfo info;

  // Behave as if 0 was passed if position is negative.
  CHECK(script1->GetPositionInfoWithLineEnds(-1, &info, line_ends));
  CHECK_EQ(13, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(0, &info, line_ends));
  CHECK_EQ(13, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(8, &info, line_ends));
  CHECK_EQ(13, info.line);
  CHECK_EQ(8, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(9, &info, line_ends));
  CHECK_EQ(14, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(9, info.line_start);
  CHECK_EQ(17, info.line_end);

  // Fail when position is larger than script size.
  CHECK(!script1->GetPositionInfoWithLineEnds(220384, &info, line_ends));

  // Without offset.

  // Behave as if 0 was passed if position is negative.
  CHECK(script1->GetPositionInfoWithLineEnds(-1, &info, line_ends,
                                             i::Script::OffsetFlag::kNoOffset));
  CHECK_EQ(0, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(0, &info, line_ends,
                                             i::Script::OffsetFlag::kNoOffset));
  CHECK_EQ(0, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(8, &info, line_ends,
                                             i::Script::OffsetFlag::kNoOffset));
  CHECK_EQ(0, info.line);
  CHECK_EQ(8, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(9, &info, line_ends,
                                             i::Script::OffsetFlag::kNoOffset));
  CHECK_EQ(1, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(9, info.line_start);
  CHECK_EQ(17, info.line_end);

  // Fail when position is larger than script size.
  CHECK(!script1->GetPositionInfoWithLineEnds(
      220384, &info, line_ends, i::Script::OffsetFlag::kNoOffset));
}

template <typename T>
void CheckMagicComments(v8::Isolate* isolate, Local<T> unbound_script,
                        const char* expected_source_url,
                        const char* expected_source_mapping_url) {
  if (expected_source_url != nullptr) {
    v8::String::Utf8Value url(isolate, unbound_script->GetSourceURL());
    CHECK_EQ(0, strcmp(expected_source_url, *url));
  } else {
    CHECK(unbound_script->GetSourceURL()->IsUndefined());
  }
  if (expected_source_mapping_url != nullptr) {
    v8::String::Utf8Value url(isolate, unbound_script->GetSourceMappingURL());
    CHECK_EQ(0, strcmp(expected_source_mapping_url, *url));
  } else {
    CHECK(unbound_script->GetSourceMappingURL()->IsUndefined());
  }
}

void SourceURLHelper(v8::Isolate* isolate, const char* source_text,
                     const char* expected_source_url,
                     const char* expected_source_mapping_url) {
  // Check scripts
  {
    Local<Script> script = v8_compile(source_text);
    CheckMagicComments(isolate, script->GetUnboundScript(), expected_source_url,
                       expected_source_mapping_url);
  }

  // Check modules
  {
    Local<v8::String> source_str = v8_str(source_text);
    // Set a different resource name with the case above to invalidate the
    // cache.
    v8::ScriptOrigin origin(v8_str("module.js"),  // resource name
                            0,                    // line offset
                            0,                    // column offset
                            true,                 // is cross origin
                            -1,                   // script id
                            Local<Value>(),       // source map URL
                            false,                // is opaque
                            false,                // is WASM
                            true);                // is ES Module
    v8::ScriptCompiler::Source source(source_str, origin, nullptr);

 
"""


```