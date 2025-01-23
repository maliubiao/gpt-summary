Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The primary goal is to analyze the `ai_language_model.cc` file and explain its functionality, its relationship to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning, identify potential user errors, and trace user interactions leading to this code.

2. **High-Level Overview:**  First, I'd quickly skim the code, paying attention to includes, class names, and method names. This gives a general idea of what the file is about. I see includes related to Mojo, Blink internals (like `ScriptState`, `ExecutionContext`, `Event`), and AI-specific modules within Blink. The class name `AILanguageModel` strongly suggests it's an interface for interacting with AI language models.

3. **Deconstruct the Code by Sections/Classes:**  The code is structured around the `AILanguageModel` class and a few helper classes. I'll analyze each significant part:

    * **Includes:** Note the key includes and what they signify:
        * `mojom/ai/...`:  This immediately indicates interaction with other processes or components, likely through Mojo IPC.
        * `ScriptState`, `ScriptPromiseResolver`: This points to integration with JavaScript.
        * `Event`:  Indicates the class can dispatch events, again linking to web API concepts.
        * `AI...`: Suggests this code is part of a larger AI subsystem within Blink.
        * `platform/heap/...`: Deals with memory management, less directly related to user-facing functionality but important for understanding the underlying system.

    * **Helper Classes (`CloneLanguageModelClient`, `CountPromptTokensClient`):** These look like specific implementations for handling the asynchronous nature of certain operations. They inherit from `AIMojoClient`, reinforcing the Mojo interaction. Their names clearly indicate their purpose: cloning and counting tokens.

    * **`AILanguageModel` Class:**  This is the core of the file. I'll go through its methods:
        * **Constructor:**  Handles initialization, binding the Mojo remote.
        * **`Trace`:** For debugging and garbage collection.
        * **`InterfaceName`:** Returns the JavaScript interface name. This is a critical link to JavaScript.
        * **`GetExecutionContext`:**  Part of the `ExecutionContextClient` interface.
        * **`prompt`:**  The primary method for sending text to the model and getting a text response. The return type `ScriptPromise<IDLString>` is a strong indicator of JavaScript integration.
        * **`promptStreaming`:** Similar to `prompt` but returns a `ReadableStream`, indicating streaming of results, another modern web API feature.
        * **`clone`:**  Creates a new, independent instance of the language model. The use of `ScriptPromise` again signifies JavaScript interaction.
        * **`countPromptTokens`:**  Calculates the number of tokens in an input string. Returns a `ScriptPromise<IDLUnsignedLongLong>`.
        * **`destroy`:**  Releases resources associated with the language model.
        * **`OnResponseComplete`:**  Handles the response from the underlying model, updating internal state (tokens).
        * **`SetInfo`:**  Sets model parameters.
        * **`GetAILanguageModelRemote`, `GetTaskRunner`, `GetCurrentTokens`:** Accessor methods for internal state.
        * **`OnContextOverflow`:**  Dispatches an event when the model's context is full.

4. **Identify Functionality:** Based on the method names and the interactions with Mojo and JavaScript promises, I can list the core functionalities:
    * Sending prompts to a language model.
    * Receiving text responses (both single responses and streaming).
    * Cloning a language model session.
    * Counting the number of tokens in a prompt.
    * Destroying a language model session.
    * Handling context overflow.

5. **Relate to JavaScript, HTML, CSS:** The key here is the `ScriptPromise` return types and the `InterfaceName()` method. This class is designed to be exposed to JavaScript.

    * **JavaScript:** The `prompt`, `promptStreaming`, `clone`, and `countPromptTokens` methods directly return JavaScript promises. The `InterfaceName()` tells us the JavaScript name (`AILanguageModel`). This allows JavaScript code to interact with the C++ AI model implementation.
    * **HTML:** While not directly interacting with HTML elements, this functionality *enhances* what's possible in HTML. For example, a website could use JavaScript and this API to generate dynamic content, provide conversational interfaces, or perform text analysis based on user input in HTML forms.
    * **CSS:**  CSS is primarily for styling. There's no direct interaction. However, the *results* of the AI model (text generated via `prompt` or `promptStreaming`) could be displayed in HTML elements and styled with CSS.

6. **Logical Reasoning (Input/Output):**  Focus on the methods that involve data processing (`prompt`, `countPromptTokens`).

    * **`prompt`:**  Input: a string (the user's prompt). Output: a promise that resolves with another string (the model's response).
    * **`countPromptTokens`:** Input: a string (the prompt). Output: a promise that resolves with a number (the token count).

7. **User/Programming Errors:** Think about common mistakes when using asynchronous APIs and dealing with resources.

    * **Using a destroyed session:**  Calling methods after `destroy()` is a common error.
    * **Not handling promise rejections:**  Failing to catch errors from the promises returned by the API.
    * **Aborting signals:**  Not understanding how abort signals work and their impact.
    * **Incorrect input:** While not explicitly handled in this *C++* code, the *model* might reject certain inputs, which would manifest as promise rejections in JavaScript.

8. **User Interaction Trace:**  Consider how a user action in a browser could lead to this C++ code being executed. Start with the user and work backward.

    * User interacts with a webpage (e.g., types into a text box and clicks a "generate" button).
    * JavaScript code on the page handles the button click.
    * The JavaScript code uses the `AILanguageModel` API (likely obtained from a factory).
    * The JavaScript calls methods like `prompt()` or `promptStreaming()`.
    * This JavaScript call triggers the corresponding C++ methods in `ai_language_model.cc`.
    * The C++ code interacts with the underlying AI model (potentially through Mojo).

9. **Refine and Organize:** Finally, structure the analysis clearly, using headings and bullet points to make it easy to read and understand. Ensure all aspects of the prompt are addressed. Double-check for accuracy and clarity. For instance, initially I might just say "handles prompting," but it's more precise to break it down into the synchronous and streaming versions and mention the promise-based nature.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive explanation covering its functionality, web technology relationships, logical reasoning, potential errors, and user interaction flow.
好的，让我们来分析一下 `blink/renderer/modules/ai/ai_language_model.cc` 这个文件。

**文件功能概要:**

`ai_language_model.cc` 文件定义了 Blink 渲染引擎中用于与 AI 语言模型进行交互的 `AILanguageModel` 类。这个类是 JavaScript 可以访问的接口，允许网页通过 JavaScript 调用来使用底层的 AI 语言模型能力。

**详细功能分解:**

1. **创建和管理 AI 语言模型会话:**
   - `AILanguageModel` 类的实例代表一个与特定 AI 语言模型的会话。
   - 它通过 Mojo IPC 与浏览器进程中的 AI 服务进行通信 (`language_model_remote_`)。
   - 构造函数 `AILanguageModel` 接收一个 `mojo::PendingRemote<mojom::blink::AILanguageModel>`，用于建立与 AI 服务的连接。
   - `destroy` 方法允许显式地销毁会话，释放资源。

2. **执行文本补全 (Prompting):**
   - `prompt` 方法接受一个文本输入 (prompt)，并异步地向 AI 模型发送请求，以获取补全的文本结果。
   - 它使用 `ScriptPromise` 来返回结果，这使得 JavaScript 可以方便地处理异步操作。
   - 它会记录 API 使用情况的指标 (通过 `base::UmaHistogramEnumeration`) 和请求大小。
   - 它支持使用 `AbortSignal` 来取消正在进行的请求。

3. **执行流式文本补全 (Streaming Prompting):**
   - `promptStreaming` 方法类似于 `prompt`，但它返回一个 `ReadableStream` 对象。
   - 这允许 JavaScript 逐步接收来自 AI 模型的文本输出，而无需等待整个响应完成。
   - 同样支持 `AbortSignal` 来取消流式请求。

4. **克隆语言模型会话:**
   - `clone` 方法允许创建一个当前语言模型会话的副本。
   - 这对于在不影响原始会话状态的情况下进行实验或并行操作非常有用。
   - 它也返回一个 `ScriptPromise`，解析为一个新的 `AILanguageModel` 对象。

5. **计算 Prompt 的 Token 数量:**
   - `countPromptTokens` 方法允许获取给定文本 prompt 在 AI 模型中会被分解成的 token 数量。
   - 这对于预估使用成本或理解模型对输入的处理方式很有用。
   - 它返回一个 `ScriptPromise`，解析为一个无符号长整型数值。

6. **处理模型响应:**
   - `OnResponseComplete` 方法在收到来自 AI 模型的响应后被调用。
   - 它更新内部状态，例如 `current_tokens_`，记录当前会话使用的 token 数量。
   - 如果模型上下文溢出 (达到最大 token 限制)，它会触发 `OnContextOverflow` 事件。

7. **设置模型信息:**
   - `SetInfo` 方法用于设置从 AI 服务接收到的模型信息，例如采样参数 (`top_k_`, `temperature_`) 和最大 token 数 (`max_tokens_`)。

8. **事件处理:**
   - `OnContextOverflow` 方法会派发一个 `contextoverflow` 事件。这允许 JavaScript 代码监听并处理模型上下文溢出的情况。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`AILanguageModel` 类是直接为 JavaScript 暴露的 API。网页开发者可以使用 JavaScript 代码来创建和操作 `AILanguageModel` 对象。

**JavaScript 示例:**

```javascript
// 假设已经通过某种方式获取了 languageModel 对象 (例如通过工厂方法)
const languageModel = ...;

// 执行文本补全
languageModel.prompt("请写一个关于猫的故事。").then(result => {
  console.log("AI 生成的故事:", result);
}).catch(error => {
  console.error("Prompt 失败:", error);
});

// 执行流式文本补全
const readableStream = languageModel.promptStreaming("继续这个故事...");
const reader = readableStream.getReader();

function read() {
  reader.read().then(({ done, value }) => {
    if (done) {
      console.log("流式传输完成。");
      return;
    }
    console.log("接收到流数据:", value);
    read();
  });
}
read();

// 计算 prompt 的 token 数量
languageModel.countPromptTokens("这是一个测试 prompt。").then(tokenCount => {
  console.log("Token 数量:", tokenCount);
});

// 克隆会话
languageModel.clone().then(clonedModel => {
  clonedModel.prompt("在克隆的会话中提问。").then(result => {
    console.log("克隆会话的响应:", result);
  });
});

// 监听上下文溢出事件
languageModel.addEventListener('contextoverflow', () => {
  console.warn("AI 模型上下文已满！");
  // 可以采取一些措施，例如清理对话历史
});

// 销毁会话
languageModel.destroy();
```

**HTML 示例:**

HTML 主要用于构建网页结构，本身不直接与 `AILanguageModel` 交互。但是，HTML 元素可以用来展示 AI 生成的内容，或者接收用户的输入作为 prompt。

```html
<!DOCTYPE html>
<html>
<head>
  <title>AI 语言模型示例</title>
</head>
<body>
  <textarea id="promptInput" placeholder="请输入你的 prompt"></textarea>
  <button id="generateButton">生成</button>
  <div id="output"></div>

  <script>
    // ... (JavaScript 代码，包括获取 languageModel 对象和处理按钮点击事件)

    document.getElementById('generateButton').addEventListener('click', () => {
      const prompt = document.getElementById('promptInput').value;
      languageModel.prompt(prompt).then(result => {
        document.getElementById('output').textContent = result;
      });
    });
  </script>
</body>
</html>
```

**CSS 示例:**

CSS 用于设置网页的样式，同样不直接与 `AILanguageModel` 交互。但是，可以使用 CSS 来美化展示 AI 生成内容的 HTML 元素。

```css
#output {
  border: 1px solid #ccc;
  padding: 10px;
  margin-top: 10px;
  white-space: pre-wrap; /* 保留换行符 */
}
```

**逻辑推理 (假设输入与输出):**

**假设输入 `prompt` 方法:**

* **输入:**  `input = "给我推荐三本关于太空探索的科幻小说。" `
* **预期输出:** 一个 `ScriptPromise`，成功 resolve 后，`result` 可能为 `"1. 《星际迷航》系列 (Star Trek)\n2. 《基地》系列 (Foundation)\n3. 《沙丘》 (Dune)"`

**假设输入 `countPromptTokens` 方法:**

* **输入:** `input = "你好世界！"`
* **预期输出:** 一个 `ScriptPromise`，成功 resolve 后，`tokenCount` 可能为 `4` (具体的 tokenization 规则取决于底层的 AI 模型)。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **在会话销毁后调用方法:**
   - **错误代码:**
     ```javascript
     languageModel.destroy();
     languageModel.prompt("再次提问").then(...); // 错误！会话已销毁
     ```
   - **说明:** 用户在调用 `destroy()` 后，尝试再次使用 `languageModel` 对象，这会导致错误，因为与底层 AI 服务的连接已经断开。

2. **未处理 Promise 的 rejection:**
   - **错误代码:**
     ```javascript
     languageModel.prompt("一个可能导致错误的 prompt").then(result => {
       console.log(result);
     }); // 缺少 .catch 来处理错误
     ```
   - **说明:** 如果 `prompt` 方法因为某种原因失败（例如，网络问题，模型错误），Promise 会被 reject。如果开发者没有提供 `.catch` 处理 rejection，可能会导致未捕获的异常。

3. **在 AbortSignal 触发后仍然尝试使用 Promise:**
   - **错误代码:**
     ```javascript
     const controller = new AbortController();
     const signal = controller.signal;
     const promise = languageModel.prompt("一个耗时的 prompt", { signal });

     controller.abort(); // 取消请求

     promise.then(result => {
       console.log(result); // 可能不会执行，或者会因为 signal 被 abort 而出错
     }).catch(error => {
       console.error(error); // 需要处理 AbortError
     });
     ```
   - **说明:** 用户通过 `AbortController` 取消了请求，但仍然假设 Promise 会正常 resolve。应该检查错误类型是否为 `AbortError`，并根据情况进行处理。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **网页的 HTML 加载，其中可能包含使用 AI 功能的 JavaScript 代码。**
3. **JavaScript 代码执行，创建 `AILanguageModel` 对象实例。**  这通常涉及到调用一个工厂方法或者通过特定的 API 获取 `AILanguageModel` 实例。在 C++ 代码中，`AILanguageModelFactory` 可能会被用来创建 `AILanguageModel` 对象。
4. **用户在网页上执行某个操作，例如：**
   - 在文本框中输入内容并点击“提问”按钮。
   - 与网页上的聊天机器人进行交互。
   - 触发了网页上某个需要 AI 能力的功能。
5. **与用户操作相关的 JavaScript 事件处理程序被触发。**
6. **事件处理程序调用 `AILanguageModel` 对象的方法，例如 `prompt` 或 `promptStreaming`，并传递用户输入作为参数。**
7. **在 `ai_language_model.cc` 中的相应 C++ 方法被调用。**
8. **C++ 代码通过 Mojo IPC 向浏览器进程中的 AI 服务发送请求。**
9. **AI 服务处理请求，并将结果返回给渲染进程。**
10. **`ai_language_model.cc` 中的回调函数（例如 `OnResponseComplete`）被调用，处理 AI 服务的响应。**
11. **Promise 被 resolve 或 reject，并将结果传递回 JavaScript 代码。**
12. **JavaScript 代码根据 Promise 的结果更新网页内容或执行其他操作。**

**调试线索:**

* **如果 JavaScript 代码调用 `AILanguageModel` 的方法时出现错误，可以在 Chrome DevTools 的 Console 中查看错误信息。**
* **可以使用断点调试 JavaScript 代码，查看 `AILanguageModel` 对象的状态和方法调用。**
* **在 C++ 代码中，可以使用 `DLOG` 或其他日志记录机制来跟踪 `AILanguageModel` 方法的执行和 Mojo 消息的传递。**
* **检查 Mojo 连接状态，确保渲染进程与浏览器进程之间的通信正常。**
* **查看 `chrome://tracing` 可以更深入地了解 Blink 内部的事件和函数调用流程。**
* **关注 `base::UmaHistogramEnumeration` 和 `base::UmaHistogramCounts1M` 记录的指标，可以了解 API 的使用情况和性能。**

总而言之，`ai_language_model.cc` 是 Blink 渲染引擎中连接 JavaScript 和底层 AI 服务的关键桥梁，它定义了 JavaScript 可以直接调用的 API，使得网页能够利用强大的 AI 语言模型能力。

### 提示词
```
这是目录为blink/renderer/modules/ai/ai_language_model.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ai/ai_language_model.h"

#include "base/check.h"
#include "base/metrics/histogram_functions.h"
#include "base/types/pass_key.h"
#include "third_party/blink/public/mojom/ai/ai_language_model.mojom-blink.h"
#include "third_party/blink/public/mojom/ai/model_streaming_responder.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/modules/ai/ai_language_model_factory.h"
#include "third_party/blink/renderer/modules/ai/ai_metrics.h"
#include "third_party/blink/renderer/modules/ai/ai_mojo_client.h"
#include "third_party/blink/renderer/modules/ai/exception_helpers.h"
#include "third_party/blink/renderer/modules/ai/model_execution_responder.h"
#include "third_party/blink/renderer/modules/event_target_modules_names.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

class CloneLanguageModelClient
    : public GarbageCollected<CloneLanguageModelClient>,
      public mojom::blink::AIManagerCreateLanguageModelClient,
      public AIMojoClient<AILanguageModel> {
 public:
  CloneLanguageModelClient(ScriptState* script_state,
                           AILanguageModel* language_model,
                           ScriptPromiseResolver<AILanguageModel>* resolver,
                           AbortSignal* signal,
                           base::PassKey<AILanguageModel> pass_key)
      : AIMojoClient(script_state, language_model, resolver, signal),
        pass_key_(pass_key),
        language_model_(language_model),
        receiver_(this, language_model->GetExecutionContext()) {
    mojo::PendingRemote<mojom::blink::AIManagerCreateLanguageModelClient>
        client_remote;
    receiver_.Bind(client_remote.InitWithNewPipeAndPassReceiver(),
                   language_model->GetTaskRunner());
    language_model_->GetAILanguageModelRemote()->Fork(std::move(client_remote));
  }
  ~CloneLanguageModelClient() override = default;

  CloneLanguageModelClient(const CloneLanguageModelClient&) = delete;
  CloneLanguageModelClient& operator=(const CloneLanguageModelClient&) = delete;

  void Trace(Visitor* visitor) const override {
    AIMojoClient::Trace(visitor);
    visitor->Trace(language_model_);
    visitor->Trace(receiver_);
  }

  // mojom::blink::AIManagerCreateLanguageModelClient implementation.
  void OnResult(
      mojo::PendingRemote<mojom::blink::AILanguageModel> language_model_remote,
      mojom::blink::AILanguageModelInfoPtr info) override {
    if (!GetResolver()) {
      return;
    }

    if (info) {
      AILanguageModel* cloned_language_model =
          MakeGarbageCollected<AILanguageModel>(
              language_model_->GetExecutionContext(),
              std::move(language_model_remote),
              language_model_->GetTaskRunner(), std::move(info),
              language_model_->GetCurrentTokens());
      GetResolver()->Resolve(cloned_language_model);
    } else {
      GetResolver()->RejectWithDOMException(
          DOMExceptionCode::kInvalidStateError,
          kExceptionMessageUnableToCloneSession);
    }

    Cleanup();
  }

  void ResetReceiver() override { receiver_.reset(); }

 private:
  base::PassKey<AILanguageModel> pass_key_;
  Member<AILanguageModel> language_model_;
  HeapMojoReceiver<mojom::blink::AIManagerCreateLanguageModelClient,
                   CloneLanguageModelClient>
      receiver_;
};

class CountPromptTokensClient
    : public GarbageCollected<CountPromptTokensClient>,
      public mojom::blink::AILanguageModelCountPromptTokensClient,
      public AIMojoClient<IDLUnsignedLongLong> {
 public:
  CountPromptTokensClient(ScriptState* script_state,
                          AILanguageModel* language_model,
                          ScriptPromiseResolver<IDLUnsignedLongLong>* resolver,
                          AbortSignal* signal,
                          const WTF::String& input)
      : AIMojoClient(script_state, language_model, resolver, signal),
        language_model_(language_model),
        receiver_(this, language_model->GetExecutionContext()) {
    mojo::PendingRemote<mojom::blink::AILanguageModelCountPromptTokensClient>
        client_remote;
    receiver_.Bind(client_remote.InitWithNewPipeAndPassReceiver(),
                   language_model->GetTaskRunner());
    language_model_->GetAILanguageModelRemote()->CountPromptTokens(
        input, std::move(client_remote));
  }
  ~CountPromptTokensClient() override = default;

  CountPromptTokensClient(const CountPromptTokensClient&) = delete;
  CountPromptTokensClient& operator=(const CountPromptTokensClient&) = delete;

  void Trace(Visitor* visitor) const override {
    AIMojoClient::Trace(visitor);
    visitor->Trace(language_model_);
    visitor->Trace(receiver_);
  }

  // mojom::blink::AILanguageModelCountPromptTokensClient implementation.
  void OnResult(uint32_t number_of_tokens) override {
    if (!GetResolver()) {
      return;
    }

    GetResolver()->Resolve(number_of_tokens);
    Cleanup();
  }

 protected:
  void ResetReceiver() override { receiver_.reset(); }

 private:
  Member<AILanguageModel> language_model_;
  HeapMojoReceiver<mojom::blink::AILanguageModelCountPromptTokensClient,
                   CountPromptTokensClient>
      receiver_;
};

}  // namespace

AILanguageModel::AILanguageModel(
    ExecutionContext* execution_context,
    mojo::PendingRemote<mojom::blink::AILanguageModel> pending_remote,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    blink::mojom::blink::AILanguageModelInfoPtr info,
    uint64_t current_tokens)
    : ExecutionContextClient(execution_context),
      current_tokens_(current_tokens),
      task_runner_(task_runner),
      language_model_remote_(execution_context) {
  language_model_remote_.Bind(std::move(pending_remote), task_runner);
  if (info) {
    SetInfo(base::PassKey<AILanguageModel>(), std::move(info));
  }
}

void AILanguageModel::Trace(Visitor* visitor) const {
  EventTarget::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  visitor->Trace(language_model_remote_);
}

const AtomicString& AILanguageModel::InterfaceName() const {
  return event_target_names::kAILanguageModel;
}

ExecutionContext* AILanguageModel::GetExecutionContext() const {
  return ExecutionContextClient::GetExecutionContext();
}

ScriptPromise<IDLString> AILanguageModel::prompt(
    ScriptState* script_state,
    const WTF::String& input,
    const AILanguageModelPromptOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    ThrowInvalidContextException(exception_state);
    return ScriptPromise<IDLString>();
  }

  base::UmaHistogramEnumeration(AIMetrics::GetAIAPIUsageMetricName(
                                    AIMetrics::AISessionType::kLanguageModel),
                                AIMetrics::AIAPI::kSessionPrompt);

  base::UmaHistogramCounts1M(AIMetrics::GetAISessionRequestSizeMetricName(
                                 AIMetrics::AISessionType::kLanguageModel),
                             int(input.CharactersSizeInBytes()));
  ScriptPromiseResolver<IDLString>* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto promise = resolver->Promise();

  if (!language_model_remote_) {
    ThrowSessionDestroyedException(exception_state);
    return promise;
  }

  AbortSignal* signal = options->getSignalOr(nullptr);
  if (signal && signal->aborted()) {
    resolver->Reject(signal->reason(script_state));
    return promise;
  }

  auto pending_remote = CreateModelExecutionResponder(
      script_state, signal, resolver, task_runner_,
      AIMetrics::AISessionType::kLanguageModel,
      WTF::BindOnce(&AILanguageModel::OnResponseComplete,
                    WrapWeakPersistent(this)));
  language_model_remote_->Prompt(input, std::move(pending_remote));
  return promise;
}

ReadableStream* AILanguageModel::promptStreaming(
    ScriptState* script_state,
    const WTF::String& input,
    const AILanguageModelPromptOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    ThrowInvalidContextException(exception_state);
    return nullptr;
  }

  base::UmaHistogramEnumeration(AIMetrics::GetAIAPIUsageMetricName(
                                    AIMetrics::AISessionType::kLanguageModel),
                                AIMetrics::AIAPI::kSessionPromptStreaming);

  base::UmaHistogramCounts1M(AIMetrics::GetAISessionRequestSizeMetricName(
                                 AIMetrics::AISessionType::kLanguageModel),
                             int(input.CharactersSizeInBytes()));

  if (!language_model_remote_) {
    ThrowSessionDestroyedException(exception_state);
    return nullptr;
  }

  AbortSignal* signal = options->getSignalOr(nullptr);
  if (signal && signal->aborted()) {
    // TODO(crbug.com/374879796): figure out how to handling aborted signal for
    // the streaming API.
    ThrowAbortedException(exception_state);
    return nullptr;
  }

  auto [readable_stream, pending_remote] =
      CreateModelExecutionStreamingResponder(
          script_state, signal, task_runner_,
          AIMetrics::AISessionType::kLanguageModel,
          WTF::BindOnce(&AILanguageModel::OnResponseComplete,
                        WrapWeakPersistent(this)));
  language_model_remote_->Prompt(input, std::move(pending_remote));
  return readable_stream;
}

ScriptPromise<AILanguageModel> AILanguageModel::clone(
    ScriptState* script_state,
    const AILanguageModelCloneOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    ThrowInvalidContextException(exception_state);
    return ScriptPromise<AILanguageModel>();
  }

  base::UmaHistogramEnumeration(AIMetrics::GetAIAPIUsageMetricName(
                                    AIMetrics::AISessionType::kLanguageModel),
                                AIMetrics::AIAPI::kSessionClone);

  ScriptPromiseResolver<AILanguageModel>* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<AILanguageModel>>(
          script_state);
  auto promise = resolver->Promise();

  if (!language_model_remote_) {
    ThrowSessionDestroyedException(exception_state);
    return promise;
  }

  AbortSignal* signal = options->getSignalOr(nullptr);
  if (signal && signal->aborted()) {
    resolver->Reject(signal->reason(script_state));
    return promise;
  }

  MakeGarbageCollected<CloneLanguageModelClient>(
      script_state, this, resolver, signal, base::PassKey<AILanguageModel>());

  return promise;
}

ScriptPromise<IDLUnsignedLongLong> AILanguageModel::countPromptTokens(
    ScriptState* script_state,
    const WTF::String& input,
    const AILanguageModelPromptOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    ThrowInvalidContextException(exception_state);
    return ScriptPromise<IDLUnsignedLongLong>();
  }

  base::UmaHistogramEnumeration(AIMetrics::GetAIAPIUsageMetricName(
                                    AIMetrics::AISessionType::kLanguageModel),
                                AIMetrics::AIAPI::kSessionCountPromptTokens);

  ScriptPromiseResolver<IDLUnsignedLongLong>* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUnsignedLongLong>>(
          script_state);
  auto promise = resolver->Promise();

  if (!language_model_remote_) {
    ThrowSessionDestroyedException(exception_state);
    return promise;
  }

  AbortSignal* signal = options->getSignalOr(nullptr);
  if (signal && signal->aborted()) {
    resolver->Reject(signal->reason(script_state));
    return promise;
  }

  MakeGarbageCollected<CountPromptTokensClient>(script_state, this, resolver,
                                                signal, input);

  return promise;
}

// TODO(crbug.com/355967885): reset the remote to destroy the session.
void AILanguageModel::destroy(ScriptState* script_state,
                              ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    ThrowInvalidContextException(exception_state);
    return;
  }

  base::UmaHistogramEnumeration(AIMetrics::GetAIAPIUsageMetricName(
                                    AIMetrics::AISessionType::kLanguageModel),
                                AIMetrics::AIAPI::kSessionDestroy);

  if (language_model_remote_) {
    language_model_remote_->Destroy();
    language_model_remote_.reset();
  }
}

void AILanguageModel::OnResponseComplete(
    mojom::blink::ModelExecutionContextInfoPtr context_info) {
  if (context_info) {
    current_tokens_ = context_info->current_tokens;
    if (context_info->did_overflow) {
      OnContextOverflow();
    }
  }
}

void AILanguageModel::SetInfo(
    std::variant<base::PassKey<AILanguageModelFactory>,
                 base::PassKey<AILanguageModel>> pass_key,
    const blink::mojom::blink::AILanguageModelInfoPtr info) {
  CHECK(info);
  top_k_ = info->sampling_params->top_k;
  temperature_ = info->sampling_params->temperature;
  max_tokens_ = info->max_tokens;
}

HeapMojoRemote<mojom::blink::AILanguageModel>&
AILanguageModel::GetAILanguageModelRemote() {
  return language_model_remote_;
}

scoped_refptr<base::SequencedTaskRunner> AILanguageModel::GetTaskRunner() {
  return task_runner_;
}

uint64_t AILanguageModel::GetCurrentTokens() {
  return current_tokens_;
}

void AILanguageModel::OnContextOverflow() {
  DispatchEvent(*Event::Create(event_type_names::kContextoverflow));
}

}  // namespace blink
```