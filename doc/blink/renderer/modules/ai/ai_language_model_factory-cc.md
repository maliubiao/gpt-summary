Response:
Let's break down the thought process for analyzing this code and generating the response.

1. **Understand the Core Task:** The primary goal is to understand the functionality of `ai_language_model_factory.cc` within the Chromium Blink rendering engine, specifically its role in creating and managing AI language models. The prompt also asks for connections to web technologies (JavaScript, HTML, CSS), logical reasoning examples, potential usage errors, and debugging guidance.

2. **Initial Code Scan and Keyword Identification:**  Quickly read through the code, looking for key terms and structures. Notice:
    * `#include` statements:  Indicate dependencies and involved concepts (e.g., `mojom::blink::AILanguageModel`, `ScriptState`, `ScriptPromise`, `AbortSignal`).
    * Class names: `AILanguageModelFactory`, `CreateLanguageModelClient`.
    * Function names: `capabilities()`, `create()`, `OnGetModelInfoComplete()`, `OnCanCreateSessionComplete()`.
    * Mojo bindings (`mojo::PendingRemote`, `HeapMojoReceiver`): Suggests inter-process communication.
    * `ScriptPromise`: Indicates asynchronous operations returning results to JavaScript.
    * `ExceptionState`:  Handles error reporting to JavaScript.
    * `AICreateMonitor`:  Likely related to tracking the creation process.
    *  `base::metrics::histogram_functions`: Implies performance tracking.

3. **Deconstruct the `AILanguageModelFactory` Class:** This is the main class, so focus on its purpose and methods.
    * **Constructor:** Takes an `AI*` object, suggesting it's part of a larger AI system.
    * **`capabilities()`:**  This method returns a `ScriptPromise` for `AILanguageModelCapabilities`. The name and return type strongly suggest it's about querying the capabilities of the language model. The internal logic using `CanCreateLanguageModel` and `GetModelInfo` confirms this.
    * **`create()`:** This is the core function for creating language model instances. It takes `AILanguageModelCreateOptions`, returns a `ScriptPromise` for `AILanguageModel`, and involves significant logic.

4. **Analyze the `create()` Method in Detail:** This is the most complex part. Break it down step-by-step:
    * **Input Validation:** Checks for a valid `ScriptState`.
    * **Promise Creation:** Sets up the asynchronous result using `ScriptPromiseResolver`.
    * **Metrics:** Logs the usage of the `create` API.
    * **Mojo Connection Check:** Ensures the connection to the backend AI service is active.
    * **Options Processing:**  This is where the parameters from JavaScript are handled.
        * **`AbortSignal`:** Handles cancellation of the creation process.
        * **`AICreateMonitor`:**  Manages progress updates.
        * **`sampling_params` (temperature, top_k):**  Handles optional sampling parameters, ensuring they are provided together.
        * **`system_prompt`:** Extracts the system prompt, handling potential conflicts if provided in both options and initial prompts.
        * **`initial_prompts`:** Processes initial prompts, enforcing the rule that only the first prompt can have a "system" role.
    * **`CreateLanguageModelClient`:**  Instantiates this helper class to handle the actual Mojo call to create the language model.

5. **Understand the `CreateLanguageModelClient` Class:** This class acts as an intermediary for the Mojo call.
    * **Inheritance:** Inherits from `AIMojoClient` and `mojom::blink::AIManagerCreateLanguageModelClient`. This indicates its role in communicating with the backend service and handling responses.
    * **Constructor:** Sets up the Mojo connection to the `AIManager`.
    * **`OnResult()`:**  Handles the response from the backend, creating an `AILanguageModel` object if successful or rejecting the promise if there's an error.

6. **Identify Connections to Web Technologies:**
    * **JavaScript:**  The methods (`capabilities`, `create`) are directly callable from JavaScript. The use of `ScriptPromise` and `ExceptionState` confirms this interaction. The `AILanguageModelCreateOptions` likely maps to a JavaScript object.
    * **HTML:**  The AI features exposed by this code might be used to enhance HTML elements or provide new interactive capabilities (e.g., AI-powered text generation within a `<textarea>`).
    * **CSS:** While less direct, the UI elements displaying AI-generated content or progress might be styled with CSS.

7. **Construct Examples of Logical Reasoning:**  Think about the conditional logic within the code, particularly in the `create()` method. Focus on the handling of optional parameters and error conditions.

8. **Identify Potential Usage Errors:** Look for scenarios where a developer might misuse the API, such as providing inconsistent parameters or not handling promise rejections.

9. **Trace User Operations for Debugging:** Consider the steps a user might take to trigger the code, starting from a web page and leading to the JavaScript API calls.

10. **Structure the Response:** Organize the findings into clear sections (Functionality, JavaScript/HTML/CSS Relationship, Logical Reasoning, Usage Errors, Debugging). Use bullet points and clear explanations. Provide concrete code examples where possible (even if simplified).

11. **Review and Refine:** Read through the generated response, ensuring accuracy, completeness, and clarity. Check for any logical inconsistencies or areas that could be explained better. For example, initially, I might not have explicitly stated that `AILanguageModelCreateOptions` likely maps to a JavaScript object, so I'd add that during the refinement phase. Also, ensure the level of detail is appropriate for the request.

By following these steps, we can systematically analyze the code and generate a comprehensive and informative response to the prompt. The key is to break down the problem into smaller, manageable parts and then synthesize the findings into a coherent whole.
好的，让我们来分析一下 `blink/renderer/modules/ai/ai_language_model_factory.cc` 这个 Chromium Blink 引擎的源代码文件。

**功能概述**

`ai_language_model_factory.cc` 文件的主要功能是**创建一个 AI 语言模型 (AILanguageModel) 的工厂类**。它负责处理创建 AI 语言模型的请求，并管理与底层 AI 服务（通过 Mojo 接口）的通信。更具体地说，它提供了以下功能：

1. **查询语言模型能力 (Capabilities):**  通过 `capabilities()` 方法，允许 JavaScript 查询当前可用的 AI 语言模型的能力，例如支持的参数范围（如 temperature, top_k）。这涉及到与后端 AI 服务通信，检查模型是否可用，并获取模型信息。
2. **创建语言模型实例 (Create):** 通过 `create()` 方法，允许 JavaScript 创建一个新的 `AILanguageModel` 实例。这涉及：
    * **参数处理:**  接收来自 JavaScript 的创建选项，包括采样参数 (temperature, top_k)、系统提示 (system prompt) 和初始提示 (initial prompts)。
    * **参数校验:**  对接收到的参数进行校验，例如确保 temperature 和 top_k 同时提供或都不提供，以及对初始提示中 system 角色的限制。
    * **与后端服务通信:**  通过 Mojo 接口，向后端 AI 服务发送创建语言模型的请求。
    * **异步处理:**  使用 Promise 处理异步创建过程，并在创建成功或失败时通知 JavaScript。
    * **监控下载进度:**  如果需要，可以监控模型下载进度，并通过回调函数通知 JavaScript。

**与 JavaScript, HTML, CSS 的关系**

这个文件直接与 **JavaScript** 功能相关，因为它暴露了 JavaScript 可以调用的 API (`capabilities()` 和 `create()`) 来与 AI 语言模型进行交互。

**举例说明:**

假设有一个网页需要使用 AI 语言模型来生成文本。开发者可以使用 JavaScript 调用 `navigator.ml.ai.languageModel.create()` 方法，并传入相应的参数：

```javascript
navigator.ml.ai.languageModel.create({
  temperature: 0.8,
  topK: 5,
  systemPrompt: "你是一个乐于助人的助手。",
  initialPrompts: [
    { role: "user", content: "请写一个关于夏天的短故事。" }
  ],
  monitor: {
    onProgress: (progress) => {
      console.log("模型下载进度:", progress.loaded / progress.total);
    }
  }
}).then(languageModel => {
  // 成功创建语言模型实例
  languageModel.generate("继续这个故事...");
}).catch(error => {
  console.error("创建语言模型失败:", error);
});
```

在这个例子中：

* `navigator.ml.ai.languageModel.create()`  的调用最终会通过 Blink 的绑定机制，路由到 `ai_language_model_factory.cc` 文件的 `create()` 方法。
* JavaScript 中的 `temperature`, `topK`, `systemPrompt`, `initialPrompts`  等参数会被传递到 C++ 代码中进行处理。
* `monitor` 对象中定义的 `onProgress` 回调函数，允许 JavaScript 监控模型下载进度。这对应于 `ai_language_model_factory.cc` 中 `AICreateMonitor` 的使用。

**与 HTML 和 CSS 的关系** 相对间接。

* **HTML:**  用户可能在 HTML 元素（如 `<textarea>` 或 `<div>`）中输入文本作为 AI 模型的输入，或者将 AI 模型生成的文本显示在 HTML 元素中。`ai_language_model_factory.cc` 负责创建和管理 AI 模型，但不直接处理 HTML 元素的渲染或交互。
* **CSS:**  可以使用 CSS 来样式化与 AI 功能相关的 UI 元素，例如显示模型下载进度的进度条，或者调整 AI 生成文本的显示样式。`ai_language_model_factory.cc` 本身不涉及 CSS。

**逻辑推理示例**

在 `create()` 方法中，对于 `initialPrompts` 的处理包含一些逻辑推理：

**假设输入:**

```javascript
// JavaScript 调用
navigator.ml.ai.languageModel.create({
  initialPrompts: [
    { role: "system", content: "你是一个代码助手。" },
    { role: "user", content: "写一个排序算法。" },
    { role: "system", content: "好的，这是冒泡排序。" } // 错误：system 角色不应该出现在非第一个 prompt 中
  ]
});
```

**逻辑推理和输出:**

`ai_language_model_factory.cc` 中的 `create()` 方法会遍历 `initialPrompts`。它会进行以下推理：

1. **第一个 Prompt 的角色:** 如果第一个 prompt 的 `role` 是 `system`，则将其内容作为系统提示处理。
2. **后续 Prompt 的角色:**  如果后续的 prompt 的 `role` 是 `system`，则会认为这是一个错误，因为系统提示应该只在第一个 prompt 中出现（或者通过 `systemPrompt` 参数直接提供）。
3. **输出:**  在这种情况下，`create()` 方法会调用 `resolver->RejectWithTypeError(kExceptionMessageSystemPromptIsNotTheFirst);`，导致 JavaScript 的 Promise 被拒绝，并抛出一个 `TypeError` 异常，提示 "System prompt is not the first."。

**用户或编程常见的使用错误**

1. **未处理 Promise 拒绝:**  开发者可能忘记处理 `create()` 方法返回的 Promise 的 `catch` 分支，导致创建失败时没有合适的错误处理。

   ```javascript
   navigator.ml.ai.languageModel.create({...})
     .then(languageModel => { /* ... */ }); // 缺少 .catch 处理
   ```

2. **错误地同时使用 `systemPrompt` 和初始 prompt 中的 system 角色:**  如果开发者在 `create()` 方法中既提供了 `systemPrompt` 参数，又在 `initialPrompts` 的第一个元素中设置了 `role: "system"`，会导致冲突。

   ```javascript
   navigator.ml.ai.languageModel.create({
     systemPrompt: "我是系统提示",
     initialPrompts: [{ role: "system", content: "我也是系统提示" }] // 错误
   });
   ```

   `ai_language_model_factory.cc` 会检测到这种情况，并抛出 `TypeError` 异常，提示 "System prompt is defined multiple times."。

3. **temperature 和 top_k 参数使用不当:**  `ai_language_model_factory.cc` 强制 `temperature` 和 `top_k` 要么同时提供，要么都不提供。如果只提供其中一个，会导致 `NotSupportedError` 异常。

   ```javascript
   navigator.ml.ai.languageModel.create({ temperature: 0.8 }); // 错误：缺少 topK
   ```

**用户操作到达这里的调试线索**

要调试与 `ai_language_model_factory.cc` 相关的代码，可以按照以下步骤追踪用户操作：

1. **用户在网页上触发了与 AI 功能相关的操作。** 例如，点击了一个“生成文本”的按钮，或者在文本框中输入了内容并提交。
2. **JavaScript 代码被执行，调用了 `navigator.ml.ai.languageModel.create({...})` 方法。** 这是进入 `ai_language_model_factory.cc` 的入口点。
3. **在 Chrome 开发者工具中设置断点。**  可以在 `ai_language_model_factory.cc` 文件的 `create()` 方法的开始处设置断点。
4. **刷新页面并重复用户的操作。** 当 JavaScript 调用 `create()` 方法时，断点会被触发。
5. **单步调试 C++ 代码。**  可以查看传入的参数值，例如 `options` 指针指向的 `AILanguageModelCreateOptions` 对象的内容。
6. **检查 Mojo 消息的发送。**  可以观察是否成功调用了 `ai_->GetAIRemote()->CreateLanguageModel(...)`，以及传递的参数。
7. **追踪 Mojo 消息的接收和处理。** 如果创建过程失败，可以检查 `CreateLanguageModelClient::OnResult()` 方法是否被调用，以及 `info` 是否为空。
8. **查看控制台输出的错误信息。**  如果 Promise 被拒绝，通常会在控制台中打印出相应的错误信息，这有助于定位问题。

**总结**

`ai_language_model_factory.cc` 是 Blink 引擎中一个关键的组件，负责创建和管理 AI 语言模型实例，并为 JavaScript 提供了与之交互的接口。理解其功能和潜在的错误用法，对于开发和调试 Web 页面中的 AI 功能至关重要。 通过跟踪 JavaScript API 调用和 C++ 代码执行，可以有效地调试相关问题。

Prompt: 
```
这是目录为blink/renderer/modules/ai/ai_language_model_factory.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/ai/ai_language_model_factory.h"

#include <optional>

#include "base/metrics/histogram_functions.h"
#include "base/types/pass_key.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/mojom/ai/ai_language_model.mojom-blink.h"
#include "third_party/blink/public/mojom/ai/ai_manager.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/ai/model_download_progress_observer.mojom-blink.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ai_create_monitor_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ai_language_model_create_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ai_language_model_initial_prompt.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_ai_language_model_initial_prompt_role.h"
#include "third_party/blink/renderer/core/events/progress_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/ai/ai.h"
#include "third_party/blink/renderer/modules/ai/ai_capability_availability.h"
#include "third_party/blink/renderer/modules/ai/ai_create_monitor.h"
#include "third_party/blink/renderer/modules/ai/ai_language_model.h"
#include "third_party/blink/renderer/modules/ai/ai_language_model_capabilities.h"
#include "third_party/blink/renderer/modules/ai/ai_metrics.h"
#include "third_party/blink/renderer/modules/ai/ai_mojo_client.h"
#include "third_party/blink/renderer/modules/ai/exception_helpers.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver.h"

namespace blink {

namespace {

mojom::blink::AILanguageModelInitialPromptRole AILanguageModelInitialPromptRole(
    V8AILanguageModelInitialPromptRole role) {
  switch (role.AsEnum()) {
    case V8AILanguageModelInitialPromptRole::Enum::kSystem:
      return mojom::blink::AILanguageModelInitialPromptRole::kSystem;
    case V8AILanguageModelInitialPromptRole::Enum::kUser:
      return mojom::blink::AILanguageModelInitialPromptRole::kUser;
    case V8AILanguageModelInitialPromptRole::Enum::kAssistant:
      return mojom::blink::AILanguageModelInitialPromptRole::kAssistant;
  }
  NOTREACHED();
}

class CreateLanguageModelClient
    : public GarbageCollected<CreateLanguageModelClient>,
      public mojom::blink::AIManagerCreateLanguageModelClient,
      public AIMojoClient<AILanguageModel> {
 public:
  CreateLanguageModelClient(
      ScriptState* script_state,
      AI* ai,
      ScriptPromiseResolver<AILanguageModel>* resolver,
      AbortSignal* signal,
      mojom::blink::AILanguageModelSamplingParamsPtr sampling_params,
      WTF::String system_prompt,
      Vector<mojom::blink::AILanguageModelInitialPromptPtr> initial_prompts,
      AICreateMonitor* monitor)
      : AIMojoClient(script_state, ai, resolver, signal),
        ai_(ai),
        monitor_(monitor),
        receiver_(this, ai->GetExecutionContext()) {
    if (monitor) {
      ai_->GetAIRemote()->AddModelDownloadProgressObserver(
          monitor->BindRemote());
    }

    mojo::PendingRemote<mojom::blink::AIManagerCreateLanguageModelClient>
        client_remote;
    receiver_.Bind(client_remote.InitWithNewPipeAndPassReceiver(),
                   ai->GetTaskRunner());
    ai_->GetAIRemote()->CreateLanguageModel(
        std::move(client_remote),
        mojom::blink::AILanguageModelCreateOptions::New(
            std::move(sampling_params), system_prompt,
            std::move(initial_prompts)));
  }
  ~CreateLanguageModelClient() override = default;

  CreateLanguageModelClient(const CreateLanguageModelClient&) = delete;
  CreateLanguageModelClient& operator=(const CreateLanguageModelClient&) =
      delete;

  void Trace(Visitor* visitor) const override {
    AIMojoClient::Trace(visitor);
    visitor->Trace(ai_);
    visitor->Trace(monitor_);
    visitor->Trace(receiver_);
  }

  void OnResult(
      mojo::PendingRemote<mojom::blink::AILanguageModel> language_model_remote,
      mojom::blink::AILanguageModelInfoPtr info) override {
    if (!GetResolver()) {
      return;
    }

    if (info) {
      AILanguageModel* language_model = MakeGarbageCollected<AILanguageModel>(
          ai_->GetExecutionContext(), std::move(language_model_remote),
          ai_->GetTaskRunner(), std::move(info), /*current_tokens=*/0);
      GetResolver()->Resolve(language_model);
    } else {
      GetResolver()->RejectWithDOMException(
          DOMExceptionCode::kInvalidStateError,
          kExceptionMessageUnableToCreateSession);
    }
    Cleanup();
  }

  void ResetReceiver() override { receiver_.reset(); }

 private:
  Member<AI> ai_;
  // The `CreateLanguageModelClient` owns the `AICreateMonitor`, so the
  // `ai.languageModel.create()` will only receive model download progress
  // update while the creation promise is pending. After the `AILanguageModel`
  // is created, the `AICreateMonitor` will be destroyed so there is no more
  // events even if the model is uninstalled and downloaded again.
  Member<AICreateMonitor> monitor_;
  HeapMojoReceiver<mojom::blink::AIManagerCreateLanguageModelClient,
                   CreateLanguageModelClient>
      receiver_;
};

}  // namespace

AILanguageModelFactory::AILanguageModelFactory(AI* ai)
    : ExecutionContextClient(ai->GetExecutionContext()),
      ai_(ai),
      task_runner_(ai->GetTaskRunner()) {}

void AILanguageModelFactory::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  visitor->Trace(ai_);
}

void AILanguageModelFactory::OnGetModelInfoComplete(
    ScriptPromiseResolver<AILanguageModelCapabilities>* resolver,
    AILanguageModelCapabilities* capabilities,
    mojom::blink::AIModelInfoPtr model_info) {
  CHECK(model_info);
  capabilities->SetDefaultTopK(model_info->default_top_k);
  capabilities->SetMaxTopK(model_info->max_top_k);
  capabilities->SetDefaultTemperature(model_info->default_temperature);
  resolver->Resolve(capabilities);
}

void AILanguageModelFactory::OnCanCreateSessionComplete(
    ScriptPromiseResolver<AILanguageModelCapabilities>* resolver,
    mojom::blink::ModelAvailabilityCheckResult check_result) {
  AICapabilityAvailability availability = HandleModelAvailabilityCheckResult(
      GetExecutionContext(), AIMetrics::AISessionType::kLanguageModel,
      check_result);
  auto* capabilities = MakeGarbageCollected<AILanguageModelCapabilities>(
      AICapabilityAvailabilityToV8(availability));
  if (availability != AICapabilityAvailability::kReadily) {
    resolver->Resolve(capabilities);
    return;
  }

  ai_->GetAIRemote()->GetModelInfo(WTF::BindOnce(
      &AILanguageModelFactory::OnGetModelInfoComplete, WrapPersistent(this),
      WrapPersistent(resolver), WrapPersistent(capabilities)));
}

ScriptPromise<AILanguageModelCapabilities> AILanguageModelFactory::capabilities(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    ThrowInvalidContextException(exception_state);
    return ScriptPromise<AILanguageModelCapabilities>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<AILanguageModelCapabilities>>(
          script_state);
  auto promise = resolver->Promise();

  base::UmaHistogramEnumeration(AIMetrics::GetAIAPIUsageMetricName(
                                    AIMetrics::AISessionType::kLanguageModel),
                                AIMetrics::AIAPI::kCanCreateSession);

  ai_->GetAIRemote()->CanCreateLanguageModel(
      WTF::BindOnce(&AILanguageModelFactory::OnCanCreateSessionComplete,
                    WrapPersistent(this), WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<AILanguageModel> AILanguageModelFactory::create(
    ScriptState* script_state,
    const AILanguageModelCreateOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    ThrowInvalidContextException(exception_state);
    return ScriptPromise<AILanguageModel>();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<AILanguageModel>>(
      script_state);
  auto promise = resolver->Promise();

  base::UmaHistogramEnumeration(AIMetrics::GetAIAPIUsageMetricName(
                                    AIMetrics::AISessionType::kLanguageModel),
                                AIMetrics::AIAPI::kCreateSession);

  if (!ai_->GetAIRemote().is_connected()) {
    RejectPromiseWithInternalError(resolver);
    return promise;
  }

  mojom::blink::AILanguageModelSamplingParamsPtr sampling_params;
  WTF::String system_prompt;
  WTF::Vector<mojom::blink::AILanguageModelInitialPromptPtr> initial_prompts;
  AbortSignal* signal = nullptr;
  AICreateMonitor* monitor = MakeGarbageCollected<AICreateMonitor>(
      GetExecutionContext(), task_runner_);

  if (options) {
    signal = options->getSignalOr(nullptr);
    if (signal && signal->aborted()) {
      resolver->Reject(signal->reason(script_state));
      return promise;
    }

    if (options->hasMonitor()) {
      std::ignore = options->monitor()->Invoke(nullptr, monitor);
    }

    // The temperature and top_k are optional, but they must be provided
    // together.
    if (!options->hasTopK() && !options->hasTemperature()) {
      sampling_params = nullptr;
    } else if (options->hasTopK() && options->hasTemperature()) {
      sampling_params = mojom::blink::AILanguageModelSamplingParams::New(
          options->topK(), options->temperature());
    } else {
      resolver->Reject(DOMException::Create(
          kExceptionMessageInvalidTemperatureAndTopKFormat,
          DOMException::GetErrorName(DOMExceptionCode::kNotSupportedError)));
      return promise;
    }

    if (options->hasSystemPrompt()) {
      system_prompt = options->systemPrompt();
    }

    if (options->hasInitialPrompts()) {
      auto& prompts = options->initialPrompts();
      if (prompts.size() > 0) {
        size_t start_index = 0;
        // Only the first prompt might have a `system` role, so it's handled
        // separately.
        auto* first_prompt = prompts.begin()->Get();
        if (first_prompt->role() ==
            V8AILanguageModelInitialPromptRole::Enum::kSystem) {
          if (options->hasSystemPrompt()) {
            // If the system prompt cannot be provided both from system prompt
            // and initial prompts, so reject with a `TypeError`.
            resolver->RejectWithTypeError(
                kExceptionMessageSystemPromptIsDefinedMultipleTimes);
            return promise;
          }
          system_prompt = first_prompt->content();
          start_index++;
        }
        for (size_t index = start_index; index < prompts.size(); ++index) {
          auto prompt = prompts[index];
          if (prompt->role() ==
              V8AILanguageModelInitialPromptRole::Enum::kSystem) {
            // If any prompt except the first one has a `system` role, reject
            // with a `TypeError`.
            resolver->RejectWithTypeError(
                kExceptionMessageSystemPromptIsNotTheFirst);
            return promise;
          }
          initial_prompts.push_back(
              mojom::blink::AILanguageModelInitialPrompt::New(
                  AILanguageModelInitialPromptRole(prompt->role()),
                  prompt->content()));
        }
      }
    }
  }

  MakeGarbageCollected<CreateLanguageModelClient>(
      script_state, ai_, resolver, signal, std::move(sampling_params),
      system_prompt, std::move(initial_prompts), monitor);

  return promise;
}

}  // namespace blink

"""

```