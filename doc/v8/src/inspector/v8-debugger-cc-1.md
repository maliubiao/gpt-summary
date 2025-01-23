Response:
Let's break down the thought process to analyze the provided C++ code and answer the user's request.

**1. Understanding the Goal:**

The core request is to understand the functionality of `v8/src/inspector/v8-debugger.cc`. The prompt provides specific instructions on what aspects to focus on: features, potential Torque implementation, relationship to JavaScript, code logic, common errors, and a summary.

**2. Initial Code Scan and High-Level Interpretation:**

I first scanned the code for keywords and structural elements to get a general sense of its purpose. Keywords like `Debugger`, `Scopes`, `StackTrace`, `Async`, `Break`, `Pause`, and `InternalProperties` immediately suggest a connection to debugging JavaScript code. The class name `V8Debugger` strongly reinforces this idea.

**3. Identifying Key Functionality Areas (Mental Grouping):**

Based on the initial scan, I started mentally grouping related functions:

* **Scope Inspection:** `functionScopes`, `generatorScopes`, `internalProperties`. These deal with inspecting the lexical environment of functions and generators.
* **Collection Inspection:** `collectionsEntries`. This seems to be about examining the contents of collections like Maps and Sets.
* **Private Member Inspection:** `privateMethods`. This focuses on accessing private members of objects.
* **Object Querying:** `queryObjects`. This function allows finding objects based on their prototype.
* **Stack Traces:** `createStackTrace`, `setAsyncCallStackDepth`, `setMaxCallStackSizeToCapture`, `storeCurrentStackTrace`, `stackTraceFor`,  `async*` functions. A significant portion of the code revolves around capturing and managing synchronous and asynchronous stack traces.
* **Breakpoints and Stepping:** The presence of `m_pauseOnAsyncCall`, `m_taskWithScheduledBreak`, and related logic hints at the implementation of breakpoint-like functionality, especially for asynchronous operations.
* **Internal Object Tracking:** `addInternalObject`. This suggests a mechanism for associating metadata with JavaScript objects for debugging purposes.
* **Utilities:** `captureStackTrace`, `currentContextGroupId`, `symbolize`. These appear to be helper functions for common tasks.

**4. Addressing Specific Instructions:**

* **Listing Features:**  This became a process of enumerating the functionalities identified in the grouping stage, explaining what each function or group of functions does.
* **Torque Check:**  The prompt explicitly asked about `.tq` files. I checked for this and noted that it's not a Torque file.
* **JavaScript Relationship and Examples:** This involved thinking about how the C++ functions would be used in a debugging context. I considered typical debugging scenarios and then wrote JavaScript code snippets demonstrating how a developer might interact with the information these C++ functions provide. For example, inspecting scopes during a breakpoint or examining the entries of a Map.
* **Code Logic and Assumptions:** For functions with more complex logic (like `collectionsEntries`), I tried to identify the inputs and outputs and trace the execution flow. The prompt explicitly asked for assumptions, so I made them where necessary (e.g., the structure of the `entries` array).
* **Common Programming Errors:** I thought about common mistakes developers make that these debugging features could help diagnose. Examples include incorrect variable scope, unexpected collection contents, and issues with asynchronous operations.
* **归纳功能 (Summary):**  This was the final step, synthesizing the individual functionalities into a concise overview of the file's purpose.

**5. Iterative Refinement and Detail Addition:**

My initial analysis was somewhat broader. I then went back through the code, looking for more specific details and edge cases. For instance, in `collectionsEntries`, I noticed the handling of key-value pairs vs. single values. For the async stack trace logic, I recognized the complexity and highlighted its role in understanding asynchronous flows.

**6. Code Reading Strategies:**

* **Following Data Flow:** For functions like `collectionsEntries`, I tracked how data was being transformed (from the input `collection` to the output `wrappedEntries`).
* **Looking for Patterns:** The `createDataProperty` function was used repeatedly, indicating a common pattern for building JavaScript objects within the debugger.
* **Understanding V8 API Usage:** While not explicitly required by the prompt, recognizing V8 API calls (like `IsObject`, `As`, `Get`, `SetPrototypeV2`, `New`, `GetHeapProfiler`, etc.) helped in understanding the code's interaction with the V8 engine.
* **Paying Attention to Error Handling:** The `FromMaybe` pattern was apparent, signaling potential failure points.

**7. Addressing Part 2:**

The prompt explicitly stated this was "Part 2" and asked for a summary. This made the final summarization step more focused on the overall purpose and key responsibilities of the file.

**Self-Correction/Refinement during the Process:**

* **Initial Overgeneralization:**  At first, I might have just said "handles debugging." I then refined this by listing specific debugging features.
* **Clarity of Examples:** I made sure the JavaScript examples were clear and directly related to the C++ functions being described.
* **Technical Accuracy:**  I reviewed my explanations to ensure they were technically correct and used appropriate terminology (e.g., "lexical environment," "prototype").

By following these steps, combining high-level understanding with detailed code analysis, and addressing each part of the user's request systematically, I was able to generate a comprehensive and informative response.
好的，让我们来分析一下 `v8/src/inspector/v8-debugger.cc` 这个文件的功能。基于你提供的代码片段，我们可以推断出它的一些关键功能。

**功能列举:**

1. **获取作用域信息 (Scope Information):**
   - `functionScopes`:  获取函数的作用域链。
   - `generatorScopes`: 获取生成器函数的作用域链。
   - 这两个函数都调用了 `getTargetScopes`，表明它们共享获取作用域信息的底层逻辑。

2. **检查集合条目 (Collection Entries Inspection):**
   - `collectionsEntries`: 用于检查类似 `Map` 或 `Set` 等集合对象的条目。
   - 它会将集合的键值对（如果适用）包装成带有 "key" 和 "value" 属性的对象。

3. **访问私有方法 (Private Methods Access):**
   - `privateMethods`:  用于获取对象的私有方法。
   - 它使用 `v8::debug::GetPrivateMembers` 来实现。

4. **获取内部属性 (Internal Properties):**
   - `internalProperties`:  这是一个综合性的函数，用于获取对象的各种内部属性，包括：
     - 通过 `v8::debug::GetInternalProperties` 获取的通用内部属性。
     - 通过 `collectionsEntries` 获取的集合条目。
     - 通过 `generatorScopes` 和 `functionScopes` 获取的作用域信息。
     - 通过 `privateMethods` 获取的私有方法。

5. **查询特定原型对象 (Query Objects by Prototype):**
   - `queryObjects`:  允许查找具有特定原型的所有对象。
   - 它使用 `v8::HeapProfiler` 来实现堆快照查询。

6. **创建堆栈跟踪 (Stack Trace Creation):**
   - `createStackTrace`:  将 V8 的 `v8::StackTrace` 对象转换为 `V8StackTraceImpl` 对象，后者是 Inspector 用于表示堆栈跟踪的内部结构。

7. **管理异步调用堆栈深度 (Asynchronous Call Stack Depth Management):**
   - `setAsyncCallStackDepth`:  设置异步操作堆栈的最大深度。这对于调试异步代码非常重要。
   - 它与 Inspector 客户端通信，告知异步调用堆栈深度的变化。

8. **管理捕获的堆栈大小 (Captured Stack Size Management):**
   - `setMaxCallStackSizeToCapture`:  设置捕获堆栈的最大大小。这影响性能和调试信息的详细程度。

9. **跟踪异步操作的父级 (Tracking Asynchronous Operation Parents):**
   - `asyncParentFor`:  查找给定堆栈跟踪 ID 的异步父级堆栈跟踪。
   - `stackTraceFor`:  根据上下文组 ID 和堆栈跟踪 ID 获取存储的异步堆栈跟踪。

10. **存储当前堆栈跟踪 (Storing Current Stack Trace):**
    - `storeCurrentStackTrace`:  捕获并存储当前的异步堆栈跟踪，以便后续分析。

11. **存储异步堆栈跟踪 (Storing Asynchronous Stack Trace):**
    - `storeStackTrace`:  存储一个已存在的 `AsyncStackTrace` 对象。

12. **处理外部异步任务的生命周期 (Handling External Asynchronous Task Lifecycle):**
    - `externalAsyncTaskStarted`:  当外部异步任务开始时被调用，记录父级堆栈信息。
    - `externalAsyncTaskFinished`: 当外部异步任务完成时被调用。

13. **处理异步任务的调度、取消、开始和完成 (Handling Asynchronous Task Scheduling, Cancellation, Start, and Finish):**
    - `asyncTaskScheduled`, `asyncTaskCanceled`, `asyncTaskStarted`, `asyncTaskFinished`:  用于跟踪 V8 内部异步任务的生命周期。这些函数有多个重载版本，分别用于处理堆栈跟踪和步进调试。

14. **异步堆栈跟踪捕获通知 (Asynchronous Stack Trace Captured Notification):**
    - `asyncStackTraceCaptured`:  在异步堆栈跟踪被捕获后调用，用于关联父级信息。

15. **取消所有异步任务 (Canceling All Asynchronous Tasks):**
    - `allAsyncTasksCanceled`:  清除所有跟踪的异步任务信息。

16. **控制脚本解析事件 (Controlling Script Parsed Events):**
    - `muteScriptParsedEvents`:  阻止发送脚本解析事件。
    - `unmuteScriptParsedEvents`:  恢复发送脚本解析事件。

17. **捕获堆栈跟踪 (Capturing Stack Trace):**
    - `captureStackTrace`:  捕获当前的同步堆栈跟踪。

18. **获取当前上下文组 ID (Getting Current Context Group ID):**
    - `currentContextGroupId`:  获取当前 V8 上下文的组 ID。

19. **管理过期的异步堆栈 (Managing Expired Asynchronous Stacks):**
    - `collectOldAsyncStacksIfNeeded`:  定期清理过期的异步堆栈跟踪，防止内存泄漏。

20. **符号化堆栈帧 (Symbolizing Stack Frames):**
    - `symbolize`:  将 V8 的 `v8::StackFrame` 对象转换为 `StackFrame` 对象，其中包含了更易于理解的函数名、源文件 URL 和行列号等信息。它使用了缓存来提高效率。

21. **设置最大异步堆栈数量 (Setting Maximum Asynchronous Stack Count):**
    - `setMaxAsyncTaskStacksForTest`:  用于测试目的，设置允许存储的最大异步堆栈数量。

22. **管理调试器 ID (Debugger ID Management):**
    - `debuggerIdFor`:  为每个上下文组生成和获取唯一的调试器 ID。

23. **添加内部对象 (Adding Internal Objects):**
    - `addInternalObject`:  将内部对象与特定的上下文关联起来。

24. **转储异步堆栈状态 (Dumping Asynchronous Stack State):**
    - `dumpAsyncTaskStacksStateForTest`:  用于测试，打印当前异步堆栈的状态信息。

25. **检查是否计划了在下一个函数调用时中断 (Checking for Scheduled Break on Next Function Call):**
    - `hasScheduledBreakOnNextFunctionCall`:  检查是否设置了在下一个函数调用时暂停执行的断点。

**关于文件类型的判断:**

根据你提供的信息，`v8/src/inspector/v8-debugger.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。如果它以 `.tq` 结尾，那才是一个 V8 Torque 源代码文件。

**与 JavaScript 的功能关系及示例:**

`v8-debugger.cc` 的核心功能是为 JavaScript 开发者提供调试能力。它暴露了许多接口，使得调试器 (例如 Chrome DevTools) 能够检查 JavaScript 代码的运行时状态。

以下是一些功能的 JavaScript 使用场景示例：

1. **查看作用域:** 当你在调试器中设置断点并暂停执行时，你可以查看当前函数及其父级函数的作用域，包括局部变量和闭包变量。`functionScopes` 和 `generatorScopes` 提供了实现此功能所需的数据。

   ```javascript
   function outer() {
     let outerVar = 10;
     function inner() {
       let innerVar = 20;
       debugger; // 在此处暂停，调试器可以查看 outerVar 和 innerVar
     }
     inner();
   }
   outer();
   ```

2. **检查集合内容:** 当你想查看 `Map` 或 `Set` 中的内容时，调试器会使用类似 `collectionsEntries` 的功能来获取这些条目并展示给你。

   ```javascript
   const myMap = new Map();
   myMap.set('a', 1);
   myMap.set('b', 2);
   debugger; // 调试器可以显示 myMap 的键值对
   ```

3. **查看私有方法:**  虽然 JavaScript 中真正的私有方法直到 ES2022 才引入，但在一些早期的提案或 V8 内部实现中，可能存在需要调试的“私有”概念。 `privateMethods` 允许检查这些。

   ```javascript
   class MyClass {
     #privateMethod() { // ES2022 私有方法
       return 'secret';
     }
     publicMethod() {
       debugger; // 调试器可能使用 privateMethods 来尝试访问 #privateMethod
     }
   }
   const instance = new MyClass();
   instance.publicMethod();
   ```

4. **查看内部属性:** 调试器可以显示对象的内部属性，例如 `[[Prototype]]`、`[[Scopes]]` 等。 `internalProperties` 提供了这些信息。

   ```javascript
   const obj = {};
   debugger; // 调试器可以显示 obj 的 [[Prototype]] 属性
   ```

5. **异步调试:**  当调试异步代码时，了解异步操作的调用堆栈非常重要。 `setAsyncCallStackDepth` 和相关的 `async*` 函数允许调试器跟踪异步操作的执行流程。

   ```javascript
   async function fetchData() {
     console.log('Fetching data...');
     await new Promise(resolve => setTimeout(resolve, 1000));
     debugger; // 调试器可以显示 fetchData 的异步调用堆栈
     return 'Data fetched';
   }
   fetchData();
   ```

**代码逻辑推理和假设输入/输出:**

以 `collectionsEntries` 函数为例：

**假设输入:**

- `context`: 一个有效的 V8 上下文。
- `collection`: 一个 JavaScript `Map` 对象，例如 `new Map([['key1', 'value1'], ['key2', 'value2']])`。

**代码逻辑:**

1. 检查 `collection` 是否是对象，并尝试获取其条目。
2. 创建一个新的 JavaScript 数组 `wrappedEntries` 来存放包装后的条目。
3. 遍历原始条目，对于每个条目：
   - 创建一个新的 JavaScript 对象 `wrapper`。
   - 如果是键值对，则在 `wrapper` 对象上设置 `key` 和 `value` 属性。
   - 如果不是键值对（例如 `Set`），则设置 `value` 属性。
   - 将 `wrapper` 对象添加到 `wrappedEntries` 数组中。

**可能的输出:**

一个 `v8::MaybeLocal<v8::Array>`，其中包含包装后的条目。对于上面的 `Map` 示例，输出的 `wrappedEntries` 数组可能看起来像这样（简化表示）：

```javascript
[
  { key: 'key1', value: 'value1' },
  { key: 'key2', value: 'value2' }
]
```

**用户常见的编程错误示例:**

1. **作用域理解错误:** 开发者可能不清楚变量在不同作用域中的访问权限，导致意外的结果。调试器可以通过 `functionScopes` 展示作用域链，帮助理解变量的查找过程。

   ```javascript
   function foo() {
     let x = 1;
     function bar() {
       // 开发者可能错误地认为可以访问外部作用域的另一个变量 y
       console.log(x); // 可以访问
       // console.log(y); // 如果 y 在 bar 的外部作用域但不是 foo 的，则无法访问
       debugger;
     }
     bar();
   }
   foo();
   ```

2. **异步操作的顺序错误:** 开发者可能错误地假设异步操作会按顺序执行，导致程序行为不符合预期。异步堆栈跟踪可以帮助理解异步操作的执行顺序和来源。

   ```javascript
   function taskA() {
     console.log('Task A started');
     setTimeout(() => {
       console.log('Task A finished');
       debugger; // 查看 taskA 的异步调用堆栈
     }, 100);
   }

   function taskB() {
     console.log('Task B started');
     setTimeout(() => {
       console.log('Task B finished');
     }, 50);
   }

   taskA();
   taskB();
   ```

3. **集合操作错误:**  开发者可能错误地假设 `Map` 或 `Set` 中存在特定的键或值。通过调试器查看集合的条目可以快速发现问题。

   ```javascript
   const mySet = new Set([1, 2, 3]);
   if (mySet.has(4)) { // 开发者可能错误地认为 4 在集合中
     console.log('Found 4!');
   }
   debugger; // 查看 mySet 的内容
   ```

**第2部分功能归纳:**

总的来说，`v8/src/inspector/v8-debugger.cc` 的主要功能是 **为 JavaScript 调试器提供底层支持，使其能够检查和控制 JavaScript 代码的执行状态**。它涵盖了作用域检查、对象属性查看（包括内部属性和私有成员）、集合内容检查、堆栈跟踪管理（包括异步操作）、以及控制脚本执行流程等关键调试特性。这个文件是 V8 Inspector 架构的核心组成部分，连接了 V8 引擎和前端调试工具。

### 提示词
```
这是目录为v8/src/inspector/v8-debugger.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/v8-debugger.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
NCTION);
}

v8::MaybeLocal<v8::Value> V8Debugger::generatorScopes(
    v8::Local<v8::Context> context, v8::Local<v8::Value> generator) {
  return getTargetScopes(context, generator, GENERATOR);
}

v8::MaybeLocal<v8::Array> V8Debugger::collectionsEntries(
    v8::Local<v8::Context> context, v8::Local<v8::Value> collection) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::Array> entries;
  bool isKeyValue = false;
  if (!collection->IsObject() || !collection.As<v8::Object>()
                                      ->PreviewEntries(&isKeyValue)
                                      .ToLocal(&entries)) {
    return v8::MaybeLocal<v8::Array>();
  }

  v8::Local<v8::Array> wrappedEntries = v8::Array::New(isolate);
  CHECK(!isKeyValue || wrappedEntries->Length() % 2 == 0);
  if (!wrappedEntries->SetPrototypeV2(context, v8::Null(isolate))
           .FromMaybe(false))
    return v8::MaybeLocal<v8::Array>();
  for (uint32_t i = 0; i < entries->Length(); i += isKeyValue ? 2 : 1) {
    v8::Local<v8::Value> item;
    if (!entries->Get(context, i).ToLocal(&item)) continue;
    v8::Local<v8::Value> value;
    if (isKeyValue && !entries->Get(context, i + 1).ToLocal(&value)) continue;
    v8::Local<v8::Object> wrapper = v8::Object::New(isolate);
    if (!wrapper->SetPrototypeV2(context, v8::Null(isolate)).FromMaybe(false))
      continue;
    createDataProperty(
        context, wrapper,
        toV8StringInternalized(isolate, isKeyValue ? "key" : "value"), item);
    if (isKeyValue) {
      createDataProperty(context, wrapper,
                         toV8StringInternalized(isolate, "value"), value);
    }
    if (!addInternalObject(context, wrapper, V8InternalValueType::kEntry))
      continue;
    createDataProperty(context, wrappedEntries, wrappedEntries->Length(),
                       wrapper);
  }
  return wrappedEntries;
}

v8::MaybeLocal<v8::Array> V8Debugger::privateMethods(
    v8::Local<v8::Context> context, v8::Local<v8::Value> receiver) {
  if (!receiver->IsObject()) {
    return v8::MaybeLocal<v8::Array>();
  }
  v8::Isolate* isolate = context->GetIsolate();
  v8::LocalVector<v8::Value> names(isolate);
  v8::LocalVector<v8::Value> values(isolate);
  int filter =
      static_cast<int>(v8::debug::PrivateMemberFilter::kPrivateMethods);
  if (!v8::debug::GetPrivateMembers(context, receiver.As<v8::Object>(), filter,
                                    &names, &values) ||
      names.empty()) {
    return v8::MaybeLocal<v8::Array>();
  }

  v8::Local<v8::Array> result = v8::Array::New(isolate);
  if (!result->SetPrototypeV2(context, v8::Null(isolate)).FromMaybe(false))
    return v8::MaybeLocal<v8::Array>();
  for (uint32_t i = 0; i < names.size(); i++) {
    v8::Local<v8::Value> name = names[i];
    v8::Local<v8::Value> value = values[i];
    DCHECK(value->IsFunction());
    v8::Local<v8::Object> wrapper = v8::Object::New(isolate);
    if (!wrapper->SetPrototypeV2(context, v8::Null(isolate)).FromMaybe(false))
      continue;
    createDataProperty(context, wrapper,
                       toV8StringInternalized(isolate, "name"), name);
    createDataProperty(context, wrapper,
                       toV8StringInternalized(isolate, "value"), value);
    if (!addInternalObject(context, wrapper,
                           V8InternalValueType::kPrivateMethod))
      continue;
    createDataProperty(context, result, result->Length(), wrapper);
  }

  if (!addInternalObject(context, result,
                         V8InternalValueType::kPrivateMethodList))
    return v8::MaybeLocal<v8::Array>();
  return result;
}

v8::MaybeLocal<v8::Array> V8Debugger::internalProperties(
    v8::Local<v8::Context> context, v8::Local<v8::Value> value) {
  v8::Local<v8::Array> properties;
  if (!v8::debug::GetInternalProperties(m_isolate, value).ToLocal(&properties))
    return v8::MaybeLocal<v8::Array>();
  v8::Local<v8::Array> entries;
  if (collectionsEntries(context, value).ToLocal(&entries)) {
    createDataProperty(context, properties, properties->Length(),
                       toV8StringInternalized(m_isolate, "[[Entries]]"));
    createDataProperty(context, properties, properties->Length(), entries);
  }

  if (value->IsGeneratorObject()) {
    v8::Local<v8::Value> scopes;
    if (generatorScopes(context, value).ToLocal(&scopes)) {
      createDataProperty(context, properties, properties->Length(),
                         toV8StringInternalized(m_isolate, "[[Scopes]]"));
      createDataProperty(context, properties, properties->Length(), scopes);
    }
  }
  if (value->IsFunction()) {
    v8::Local<v8::Function> function = value.As<v8::Function>();
    v8::Local<v8::Value> scopes;
    if (functionScopes(context, function).ToLocal(&scopes)) {
      createDataProperty(context, properties, properties->Length(),
                         toV8StringInternalized(m_isolate, "[[Scopes]]"));
      createDataProperty(context, properties, properties->Length(), scopes);
    }
  }
  v8::Local<v8::Array> private_methods;
  if (privateMethods(context, value).ToLocal(&private_methods)) {
    createDataProperty(context, properties, properties->Length(),
                       toV8StringInternalized(m_isolate, "[[PrivateMethods]]"));
    createDataProperty(context, properties, properties->Length(),
                       private_methods);
  }
  return properties;
}

v8::Local<v8::Array> V8Debugger::queryObjects(v8::Local<v8::Context> context,
                                              v8::Local<v8::Object> prototype) {
  v8::Isolate* isolate = context->GetIsolate();
  std::vector<v8::Global<v8::Object>> v8_objects;
  MatchPrototypePredicate predicate(m_inspector, context, prototype);
  isolate->GetHeapProfiler()->QueryObjects(context, &predicate, &v8_objects);

  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::Local<v8::Array> resultArray = v8::Array::New(
      m_inspector->isolate(), static_cast<int>(v8_objects.size()));
  for (size_t i = 0; i < v8_objects.size(); ++i) {
    createDataProperty(context, resultArray, static_cast<int>(i),
                       v8_objects[i].Get(isolate));
  }
  return resultArray;
}

std::unique_ptr<V8StackTraceImpl> V8Debugger::createStackTrace(
    v8::Local<v8::StackTrace> v8StackTrace) {
  return V8StackTraceImpl::create(
      this, v8StackTrace, V8StackTraceImpl::kDefaultMaxCallStackSizeToCapture);
}

void V8Debugger::setAsyncCallStackDepth(V8DebuggerAgentImpl* agent, int depth) {
  if (depth <= 0)
    m_maxAsyncCallStackDepthMap.erase(agent);
  else
    m_maxAsyncCallStackDepthMap[agent] = depth;

  int maxAsyncCallStackDepth = 0;
  for (const auto& pair : m_maxAsyncCallStackDepthMap) {
    if (pair.second > maxAsyncCallStackDepth)
      maxAsyncCallStackDepth = pair.second;
  }

  if (m_maxAsyncCallStackDepth == maxAsyncCallStackDepth) return;
  // TODO(dgozman): ideally, this should be per context group.
  m_maxAsyncCallStackDepth = maxAsyncCallStackDepth;
  m_inspector->client()->maxAsyncCallStackDepthChanged(
      m_maxAsyncCallStackDepth);
  if (!maxAsyncCallStackDepth) allAsyncTasksCanceled();
  v8::debug::SetAsyncEventDelegate(m_isolate,
                                   maxAsyncCallStackDepth ? this : nullptr);
}

void V8Debugger::setMaxCallStackSizeToCapture(V8RuntimeAgentImpl* agent,
                                              int size) {
  if (size < 0) {
    m_maxCallStackSizeToCaptureMap.erase(agent);
  } else {
    m_maxCallStackSizeToCaptureMap[agent] = size;
  }

  // The following logic is a bit complicated to decipher because we
  // want to retain backwards compatible semantics:
  //
  // (a) When no `Runtime` domain is enabled, we stick to the default
  //     maximum call stack size, but don't let V8 collect stack traces
  //     for uncaught exceptions.
  // (b) When `Runtime` is enabled for at least one front-end, we compute
  //     the maximum of the requested maximum call stack sizes of all the
  //     front-ends whose `Runtime` domains are enabled (which might be 0),
  //     and ask V8 to collect stack traces for uncaught exceptions.
  //
  // The latter allows performance test automation infrastructure to drive
  // browser via `Runtime` domain while still minimizing the performance
  // overhead of having the inspector attached - see the relevant design
  // document https://bit.ly/v8-cheaper-inspector-stack-traces for more
  if (m_maxCallStackSizeToCaptureMap.empty()) {
    m_maxCallStackSizeToCapture =
        V8StackTraceImpl::kDefaultMaxCallStackSizeToCapture;
    m_isolate->SetCaptureStackTraceForUncaughtExceptions(false);
  } else {
    m_maxCallStackSizeToCapture = 0;
    for (auto const& pair : m_maxCallStackSizeToCaptureMap) {
      if (m_maxCallStackSizeToCapture < pair.second)
        m_maxCallStackSizeToCapture = pair.second;
    }
    m_isolate->SetCaptureStackTraceForUncaughtExceptions(
        m_maxCallStackSizeToCapture > 0, m_maxCallStackSizeToCapture);
  }
}

void V8Debugger::asyncParentFor(int stackTraceId,
                                std::shared_ptr<AsyncStackTrace>* asyncParent,
                                V8StackTraceId* externalParent) const {
  auto it = m_asyncParents.find(stackTraceId);
  if (it != m_asyncParents.end()) {
    *asyncParent = it->second.lock();
    if (*asyncParent && (*asyncParent)->isEmpty()) {
      *asyncParent = (*asyncParent)->parent().lock();
    }
  } else {
    auto externalIt = std::find_if(
        m_externalParents.begin(), m_externalParents.end(),
        [stackTraceId](const auto& p) { return p.first == stackTraceId; });
    if (externalIt != m_externalParents.end()) {
      *externalParent = externalIt->second;
    }
  }
  DCHECK_IMPLIES(!externalParent->IsInvalid(), !*asyncParent);
  DCHECK_IMPLIES(*asyncParent, externalParent->IsInvalid());
}

std::shared_ptr<AsyncStackTrace> V8Debugger::stackTraceFor(
    int contextGroupId, const V8StackTraceId& id) {
  if (debuggerIdFor(contextGroupId).pair() != id.debugger_id) return nullptr;
  auto it = m_storedStackTraces.find(id.id);
  if (it == m_storedStackTraces.end()) return nullptr;
  return it->second.lock();
}

V8StackTraceId V8Debugger::storeCurrentStackTrace(
    const StringView& description) {
  if (!m_maxAsyncCallStackDepth) return V8StackTraceId();

  v8::HandleScope scope(m_isolate);
  int contextGroupId = currentContextGroupId();
  if (!contextGroupId) return V8StackTraceId();

  std::shared_ptr<AsyncStackTrace> asyncStack =
      AsyncStackTrace::capture(this, toString16(description));
  if (!asyncStack) return V8StackTraceId();

  uintptr_t id = AsyncStackTrace::store(this, asyncStack);

  m_allAsyncStacks.push_back(std::move(asyncStack));
  collectOldAsyncStacksIfNeeded();

  bool shouldPause =
      m_pauseOnAsyncCall && contextGroupId == m_targetContextGroupId;
  if (shouldPause) {
    m_pauseOnAsyncCall = false;
    v8::debug::ClearStepping(m_isolate);  // Cancel step into.
  }
  return V8StackTraceId(id, debuggerIdFor(contextGroupId).pair(), shouldPause);
}

uintptr_t V8Debugger::storeStackTrace(
    std::shared_ptr<AsyncStackTrace> asyncStack) {
  uintptr_t id = ++m_lastStackTraceId;
  m_storedStackTraces[id] = asyncStack;
  return id;
}

void V8Debugger::externalAsyncTaskStarted(const V8StackTraceId& parent) {
  if (!m_maxAsyncCallStackDepth || parent.IsInvalid()) return;
  m_currentExternalParent.push_back(parent);
  m_currentAsyncParent.emplace_back();
  m_currentTasks.push_back(reinterpret_cast<void*>(parent.id));

  if (!parent.should_pause) return;
  bool didHaveBreak = hasScheduledBreakOnNextFunctionCall();
  m_externalAsyncTaskPauseRequested = true;
  if (didHaveBreak) return;
  m_targetContextGroupId = currentContextGroupId();
  v8::debug::SetBreakOnNextFunctionCall(m_isolate);
}

void V8Debugger::externalAsyncTaskFinished(const V8StackTraceId& parent) {
  if (!m_maxAsyncCallStackDepth || m_currentExternalParent.empty()) return;
  m_currentExternalParent.pop_back();
  m_currentAsyncParent.pop_back();
  DCHECK(m_currentTasks.back() == reinterpret_cast<void*>(parent.id));
  m_currentTasks.pop_back();

  if (!parent.should_pause) return;
  m_externalAsyncTaskPauseRequested = false;
  if (hasScheduledBreakOnNextFunctionCall()) return;
  v8::debug::ClearBreakOnNextFunctionCall(m_isolate);
}

void V8Debugger::asyncTaskScheduled(const StringView& taskName, void* task,
                                    bool recurring) {
  asyncTaskScheduledForStack(taskName, task, recurring);
  asyncTaskCandidateForStepping(task);
}

void V8Debugger::asyncTaskCanceled(void* task) {
  asyncTaskCanceledForStack(task);
  asyncTaskCanceledForStepping(task);
}

void V8Debugger::asyncTaskStarted(void* task) {
  asyncTaskStartedForStack(task);
  asyncTaskStartedForStepping(task);
}

void V8Debugger::asyncTaskFinished(void* task) {
  asyncTaskFinishedForStepping(task);
  asyncTaskFinishedForStack(task);
}

void V8Debugger::asyncTaskScheduledForStack(const StringView& taskName,
                                            void* task, bool recurring,
                                            bool skipTopFrame) {
#ifdef V8_USE_PERFETTO
  TRACE_EVENT(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
              "v8::Debugger::AsyncTaskScheduled",
              perfetto::Flow::ProcessScoped(reinterpret_cast<uintptr_t>(task)));
#endif  // V8_USE_PERFETTO
  if (!m_maxAsyncCallStackDepth) return;
  v8::HandleScope scope(m_isolate);
  std::shared_ptr<AsyncStackTrace> asyncStack =
      AsyncStackTrace::capture(this, toString16(taskName), skipTopFrame);
  if (asyncStack) {
    m_asyncTaskStacks[task] = asyncStack;
    if (recurring) m_recurringTasks.insert(task);
    m_allAsyncStacks.push_back(std::move(asyncStack));
    collectOldAsyncStacksIfNeeded();
  }
}

void V8Debugger::asyncTaskCanceledForStack(void* task) {
#ifdef V8_USE_PERFETTO
  TRACE_EVENT(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
              "v8::Debugger::AsyncTaskCanceled",
              perfetto::Flow::ProcessScoped(reinterpret_cast<uintptr_t>(task)));
#endif  // V8_USE_PERFETTO
  if (!m_maxAsyncCallStackDepth) return;
  m_asyncTaskStacks.erase(task);
  m_recurringTasks.erase(task);
}

void V8Debugger::asyncTaskStartedForStack(void* task) {
#ifdef V8_USE_PERFETTO
  TRACE_EVENT_BEGIN(
      TRACE_DISABLED_BY_DEFAULT("v8.inspector"), "v8::Debugger::AsyncTaskRun",
      perfetto::Flow::ProcessScoped(reinterpret_cast<uintptr_t>(task)));
#endif  // V8_USE_PERFETTO
  if (!m_maxAsyncCallStackDepth) return;
  // Needs to support following order of events:
  // - asyncTaskScheduled
  //   <-- attached here -->
  // - asyncTaskStarted
  // - asyncTaskCanceled <-- canceled before finished
  //   <-- async stack requested here -->
  // - asyncTaskFinished
  m_currentTasks.push_back(task);
  AsyncTaskToStackTrace::iterator stackIt = m_asyncTaskStacks.find(task);
  if (stackIt != m_asyncTaskStacks.end() && !stackIt->second.expired()) {
    std::shared_ptr<AsyncStackTrace> stack(stackIt->second);
    m_currentAsyncParent.push_back(stack);
  } else {
    m_currentAsyncParent.emplace_back();
  }
  m_currentExternalParent.emplace_back();
}

void V8Debugger::asyncTaskFinishedForStack(void* task) {
#ifdef V8_USE_PERFETTO
  TRACE_EVENT_END0(TRACE_DISABLED_BY_DEFAULT("v8.inspector"),
                   "v8::Debugger::AsyncTaskRun");
#endif  // V8_USE_PERFETTO
  if (!m_maxAsyncCallStackDepth) return;
  // We could start instrumenting half way and the stack is empty.
  if (m_currentTasks.empty()) return;
  DCHECK(m_currentTasks.back() == task);
  m_currentTasks.pop_back();

  m_currentAsyncParent.pop_back();
  m_currentExternalParent.pop_back();

  if (m_recurringTasks.find(task) == m_recurringTasks.end()) {
    asyncTaskCanceledForStack(task);
  }
}

void V8Debugger::asyncTaskCandidateForStepping(void* task) {
  if (!m_pauseOnAsyncCall) return;
  int contextGroupId = currentContextGroupId();
  if (contextGroupId != m_targetContextGroupId) return;
  m_taskWithScheduledBreak = task;
  m_pauseOnAsyncCall = false;
  v8::debug::ClearStepping(m_isolate);  // Cancel step into.
}

void V8Debugger::asyncTaskStartedForStepping(void* task) {
  // TODO(kozyatinskiy): we should search task in async chain to support
  // blackboxing.
  if (task != m_taskWithScheduledBreak) return;
  bool didHaveBreak = hasScheduledBreakOnNextFunctionCall();
  m_taskWithScheduledBreakPauseRequested = true;
  if (didHaveBreak) return;
  m_targetContextGroupId = currentContextGroupId();
  v8::debug::SetBreakOnNextFunctionCall(m_isolate);
}

void V8Debugger::asyncTaskFinishedForStepping(void* task) {
  if (task != m_taskWithScheduledBreak) return;
  m_taskWithScheduledBreak = nullptr;
  m_taskWithScheduledBreakPauseRequested = false;
  if (hasScheduledBreakOnNextFunctionCall()) return;
  v8::debug::ClearBreakOnNextFunctionCall(m_isolate);
}

void V8Debugger::asyncTaskCanceledForStepping(void* task) {
  asyncTaskFinishedForStepping(task);
}

void V8Debugger::asyncStackTraceCaptured(int id) {
  auto async_stack = currentAsyncParent();
  if (async_stack) {
    m_asyncParents.emplace(id, async_stack);
  }
  auto externalParent = currentExternalParent();
  if (!externalParent.IsInvalid()) {
    m_externalParents.push_back(std::make_pair(id, externalParent));
  }
}

void V8Debugger::allAsyncTasksCanceled() {
  m_asyncTaskStacks.clear();
  m_recurringTasks.clear();
  m_currentAsyncParent.clear();
  m_currentExternalParent.clear();
  m_currentTasks.clear();
  m_currentAsyncParent.clear();
  m_externalParents.clear();

  m_allAsyncStacks.clear();
}

void V8Debugger::muteScriptParsedEvents() {
  ++m_ignoreScriptParsedEventsCounter;
}

void V8Debugger::unmuteScriptParsedEvents() {
  --m_ignoreScriptParsedEventsCounter;
  DCHECK_GE(m_ignoreScriptParsedEventsCounter, 0);
}

std::unique_ptr<V8StackTraceImpl> V8Debugger::captureStackTrace(
    bool fullStack) {
  int contextGroupId = currentContextGroupId();
  if (!contextGroupId) return nullptr;

  int stackSize = 1;
  if (fullStack) {
    stackSize = V8StackTraceImpl::kDefaultMaxCallStackSizeToCapture;
  } else {
    m_inspector->forEachSession(
        contextGroupId, [this, &stackSize](V8InspectorSessionImpl* session) {
          if (session->runtimeAgent()->enabled())
            stackSize = maxCallStackSizeToCapture();
        });
  }
  return V8StackTraceImpl::capture(this, stackSize);
}

int V8Debugger::currentContextGroupId() {
  if (!m_isolate->InContext()) return 0;
  v8::HandleScope handleScope(m_isolate);
  return m_inspector->contextGroupId(m_isolate->GetCurrentContext());
}

void V8Debugger::collectOldAsyncStacksIfNeeded() {
  if (m_allAsyncStacks.size() <= m_maxAsyncCallStacks) return;
  size_t halfOfLimitRoundedUp =
      m_maxAsyncCallStacks / 2 + m_maxAsyncCallStacks % 2;
  while (m_allAsyncStacks.size() > halfOfLimitRoundedUp) {
    m_allAsyncStacks.pop_front();
  }
  cleanupExpiredWeakPointers(m_asyncTaskStacks);
  cleanupExpiredWeakPointers(m_cachedStackFrames);
  cleanupExpiredWeakPointers(m_asyncParents);
  cleanupExpiredWeakPointers(m_storedStackTraces);
  for (auto it = m_recurringTasks.begin(); it != m_recurringTasks.end();) {
    if (m_asyncTaskStacks.find(*it) == m_asyncTaskStacks.end()) {
      it = m_recurringTasks.erase(it);
    } else {
      ++it;
    }
  }
  if (m_externalParents.size() > kMaxExternalParents) {
    size_t halfOfExternalParents = (m_externalParents.size() + 1) / 2;
    while (m_externalParents.size() > halfOfExternalParents) {
      m_externalParents.pop_front();
    }
  }
}

std::shared_ptr<StackFrame> V8Debugger::symbolize(
    v8::Local<v8::StackFrame> v8Frame) {
  int scriptId = v8Frame->GetScriptId();
  auto location = v8Frame->GetLocation();
  int lineNumber = location.GetLineNumber();
  int columnNumber = location.GetColumnNumber();
  CachedStackFrameKey key{scriptId, lineNumber, columnNumber};
  auto functionName = toProtocolString(isolate(), v8Frame->GetFunctionName());
  auto it = m_cachedStackFrames.find(key);
  if (it != m_cachedStackFrames.end() && !it->second.expired()) {
    auto stackFrame = it->second.lock();
    if (stackFrame->functionName() == functionName) {
      DCHECK_EQ(
          stackFrame->sourceURL(),
          toProtocolString(isolate(), v8Frame->GetScriptNameOrSourceURL()));
      return stackFrame;
    }
  }
  auto sourceURL =
      toProtocolString(isolate(), v8Frame->GetScriptNameOrSourceURL());
  auto hasSourceURLComment =
      v8Frame->GetScriptName() != v8Frame->GetScriptNameOrSourceURL();
  auto stackFrame = std::make_shared<StackFrame>(
      std::move(functionName), scriptId, std::move(sourceURL), lineNumber,
      columnNumber, hasSourceURLComment);
  m_cachedStackFrames.emplace(key, stackFrame);
  return stackFrame;
}

void V8Debugger::setMaxAsyncTaskStacksForTest(int limit) {
  m_maxAsyncCallStacks = 0;
  collectOldAsyncStacksIfNeeded();
  m_maxAsyncCallStacks = limit;
}

internal::V8DebuggerId V8Debugger::debuggerIdFor(int contextGroupId) {
  auto it = m_contextGroupIdToDebuggerId.find(contextGroupId);
  if (it != m_contextGroupIdToDebuggerId.end()) return it->second;
  internal::V8DebuggerId debuggerId =
      internal::V8DebuggerId::generate(m_inspector);
  m_contextGroupIdToDebuggerId.insert(
      it, std::make_pair(contextGroupId, debuggerId));
  return debuggerId;
}

bool V8Debugger::addInternalObject(v8::Local<v8::Context> context,
                                   v8::Local<v8::Object> object,
                                   V8InternalValueType type) {
  int contextId = InspectedContext::contextId(context);
  InspectedContext* inspectedContext = m_inspector->getContext(contextId);
  return inspectedContext ? inspectedContext->addInternalObject(object, type)
                          : false;
}

void V8Debugger::dumpAsyncTaskStacksStateForTest() {
  fprintf(stdout, "Async stacks count: %zu\n", m_allAsyncStacks.size());
  fprintf(stdout, "Scheduled async tasks: %zu\n", m_asyncTaskStacks.size());
  fprintf(stdout, "Recurring async tasks: %zu\n", m_recurringTasks.size());
  fprintf(stdout, "\n");
}

bool V8Debugger::hasScheduledBreakOnNextFunctionCall() const {
  return m_pauseOnNextCallRequested || m_taskWithScheduledBreakPauseRequested ||
         m_externalAsyncTaskPauseRequested;
}

}  // namespace v8_inspector
```