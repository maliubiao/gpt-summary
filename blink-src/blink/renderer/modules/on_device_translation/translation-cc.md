Response:
Let's break down the thought process for analyzing the `translation.cc` file.

1. **Understand the Goal:** The request asks for a functional overview of the file, its relation to web technologies, potential logic, common errors, and user interaction leading to its execution.

2. **Initial Scan and Keywords:**  A quick scan reveals key terms: `translation`, `LanguageTranslator`, `LanguageDetector`, `ScriptPromise`, `mojom`, `javascript`, `html`, `css`, `developer.chrome.com/docs/ai/translator-api`. These immediately suggest the file is about on-device translation functionality exposed to JavaScript within the Chromium browser.

3. **Identify Core Functionality:**  The presence of `canTranslate`, `createTranslator`, `canDetect`, and `createDetector` as public methods of the `Translation` class strongly indicates the core functionalities:
    * Checking if translation between languages is possible.
    * Creating an object to perform translation.
    * Checking if language detection is possible.
    * Creating an object to perform language detection.

4. **Examine Class Structure and Dependencies:**
    * **`Translation` class:** This is the main entry point and seems to manage the interaction with the underlying translation service. It holds a `translation_manager_remote_` which suggests communication with a separate browser process.
    * **`CreateTranslatorClient` class:** This looks like a helper class to handle the asynchronous process of creating a translator. It implements a Mojo interface (`TranslationManagerCreateTranslatorClient`) for communication.
    * **`LanguageTranslator` and `LanguageDetector`:** These are likely the classes that perform the actual translation and detection, respectively. They are created and managed by the `Translation` class.
    * **Mojo:** The use of `mojo::PendingReceiver`, `mojo::PendingRemote`, and the `.mojom-blink.h` includes indicate inter-process communication using the Mojo framework.
    * **`ScriptPromise`:** This signals that the functions are asynchronous and return promises to JavaScript.
    * **`TranslationLanguageOptions`:**  This likely holds the source and target languages for translation.

5. **Analyze Individual Functions:**

    * **`canTranslate`:**  It checks if a translation between the given languages is possible. It uses `GetTranslationManagerRemote()` to communicate with the browser process. The callback function handles different `CanCreateTranslatorResult` values, mapping them to `V8TranslationAvailability` enum values (`kReadily`, `kAfterDownload`, `kNo`). This clearly relates to JavaScript through the returned `ScriptPromise` and the `V8TranslationAvailability` type.

    * **`createTranslator`:**  It initiates the creation of a `LanguageTranslator`. It uses the `CreateTranslatorClient` to handle the asynchronous communication. Error handling is evident in the `OnResult` method of `CreateTranslatorClient`, which rejects the promise with an error message if creation fails. This directly interacts with JavaScript by providing a `LanguageTranslator` object.

    * **`canDetect`:** This function appears simpler and always resolves with `kReadily`. This suggests on-device language detection is generally assumed to be available.

    * **`createDetector`:** This function creates a `LanguageDetector` object and resolves the promise immediately.

6. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:** The most direct link is through the `ScriptPromise` return types of the public methods. JavaScript code can call these methods and use `.then()` and `.catch()` to handle the results. The `TranslationLanguageOptions` object is likely created and passed from JavaScript.
    * **HTML:** While not directly manipulating HTML elements, the translation functionality is triggered by user actions within the browser, which are often initiated through HTML elements (e.g., clicking a "translate" button). The translated text will ultimately be rendered in the HTML.
    * **CSS:** CSS isn't directly involved in the *logic* of translation, but it controls the styling of the original and translated content. The appearance of the translated text is determined by CSS rules.

7. **Consider Logic and Assumptions:**

    * **Asynchronous Operations:** The use of `ScriptPromise` and Mojo indicates asynchronous communication with another process (likely the browser process or a separate service). The `CreateTranslatorClient` manages the callback for the `createTranslator` function.
    * **Error Handling:** The code includes checks for valid execution contexts and handles errors returned from the translation service (e.g., invalid languages, service crashes). The `ConvertCreateTranslatorErrorToDebugString` function provides user-friendly error messages.
    * **Language Availability:** The `canTranslate` function determines if the necessary language models are available.

8. **Identify Potential User/Programming Errors:**

    * **Invalid Language Codes:** Providing incorrect or unsupported language codes to `canTranslate` or `createTranslator`.
    * **Calling Methods in Invalid Context:**  Trying to use the API before the execution context is valid.
    * **Too Many Requests:** The error message "Too many Translator API requests are queued" suggests a potential for rate-limiting or exceeding usage quotas.

9. **Trace User Interaction:** Think about the sequence of events that would lead to this code being executed:

    * A user visits a webpage.
    * The webpage contains JavaScript that uses the Translation API.
    * The JavaScript calls `navigator.ml.translation.canTranslate()` or `navigator.ml.translation.createTranslator()`. (Note: the exact API surface might differ, but the principle is the same.)
    * The browser receives this request and routes it to the Blink rendering engine.
    * The `Translation` class in `translation.cc` is invoked to handle the request.

10. **Review and Refine:**  Read through the analysis, ensuring accuracy and completeness. Organize the information logically according to the request's prompts. Add concrete examples where appropriate. Double-check assumptions and clarify any ambiguous points. For example, initially, I might not have explicitly mentioned the role of the browser process, but recognizing the Mojo usage helps clarify the architecture.
好的，让我们详细分析一下 `blink/renderer/modules/on_device_translation/translation.cc` 这个文件。

**文件功能概述**

`translation.cc` 文件是 Chromium Blink 渲染引擎中，负责提供**设备端（On-Device）翻译**功能的核心模块。它主要做了以下几件事情：

1. **提供 JavaScript API 接口:**  该文件实现了可以被 JavaScript 代码调用的 API，允许网页发起和管理设备端翻译请求。这些 API 主要围绕着创建和使用翻译器（Translator）和语言检测器（Language Detector）。
2. **管理与浏览器进程的通信:**  它通过 Mojo 接口与浏览器进程中的 TranslationManager 服务进行通信，以请求创建翻译器和检测器，并获取翻译能力信息。
3. **封装设备端翻译逻辑:**  虽然具体的翻译和检测逻辑可能在更底层的库中实现，但该文件负责协调和管理这些逻辑的调用，处理错误，并以 Promise 的形式将结果返回给 JavaScript。
4. **处理异步操作:**  翻译和语言检测通常是异步操作，该文件使用 `ScriptPromise` 来处理这些异步操作，使得 JavaScript 代码能够以非阻塞的方式调用翻译功能。
5. **错误处理和状态管理:**  它负责处理创建翻译器或检测器时可能出现的各种错误，例如不支持的语言、服务崩溃、策略限制等，并将这些错误信息转化为 JavaScript 可以理解的异常。

**与 JavaScript, HTML, CSS 的关系**

这个文件提供的功能直接与 JavaScript 相关，并通过 JavaScript 间接地影响 HTML 和 CSS 的展示。

* **与 JavaScript 的关系 (直接)**

   * **API 暴露:**  该文件中的 `Translation` 类提供了 `canTranslate`, `createTranslator`, `canDetect`, `createDetector` 等方法，这些方法会被暴露给 JavaScript，通常会通过 `navigator.ml.translation` 这样的全局对象访问 (具体 API 可能有所调整，但原理相同)。
   * **异步操作和 Promise:**  所有提供给 JavaScript 的方法都返回 `ScriptPromise` 对象。这使得 JavaScript 能够异步地调用翻译和检测功能，并在操作完成后通过 `.then()` 和 `.catch()` 处理结果或错误。
   * **数据传递:** JavaScript 代码会通过参数 (例如 `TranslationLanguageOptions`) 将源语言、目标语言等信息传递给 C++ 代码。C++ 代码也会将翻译结果或错误信息通过 Promise 传递回 JavaScript。

   **举例说明:**

   ```javascript
   // JavaScript 代码
   navigator.ml.translation.canTranslate({ sourceLanguage: 'en', targetLanguage: 'zh' })
     .then(availability => {
       if (availability.value === 'kReadily') {
         console.log('英译中可以立即使用');
       } else if (availability.value === 'kAfterDownload') {
         console.log('英译中需要下载模型');
       } else {
         console.log('英译中不支持');
       }
     });

   navigator.ml.translation.createTranslator({ sourceLanguage: 'en', targetLanguage: 'zh' })
     .then(translator => {
       // translator 是一个 LanguageTranslator 对象，可以调用其 translate 方法
       // ...
     })
     .catch(error => {
       console.error('创建翻译器失败:', error);
     });
   ```

* **与 HTML 的关系 (间接)**

   * **翻译内容展示:**  设备端翻译的最终目的是将网页上的文本内容翻译成用户所需的语言，并将翻译后的内容展示在 HTML 页面上。JavaScript 代码在获取翻译结果后，会操作 DOM (Document Object Model) 来更新 HTML 元素的内容。
   * **用户交互触发:**  用户的操作，例如点击翻译按钮、选择翻译语言等，通常会通过 JavaScript 代码触发对 `navigator.ml.translation` API 的调用。

* **与 CSS 的关系 (间接)**

   * **翻译内容样式:**  CSS 负责控制网页元素的样式。翻译后的文本会继承或应用相关的 CSS 样式，以确保在页面上正确地呈现。

**逻辑推理 (假设输入与输出)**

假设 JavaScript 代码调用了 `canTranslate` 方法：

* **假设输入:**
    * `script_state`: 当前 JavaScript 的执行状态。
    * `options`: 一个 `TranslationLanguageOptions` 对象，包含 `sourceLanguage: "en"` 和 `targetLanguage: "fr"`。
    * `exception_state`: 用于报告异常的状态对象。

* **逻辑推理:**
    1. `canTranslate` 方法被调用，检查 `script_state` 是否有效。
    2. 创建一个 `ScriptPromiseResolver` 和对应的 `ScriptPromise`。
    3. 获取 `TranslationManagerRemote` 的远程接口。
    4. 调用 `translation_manager_remote_->CanCreateTranslator("en", "fr", ...)`，向浏览器进程发送请求，询问是否可以创建英译法的翻译器。
    5. 浏览器进程的 TranslationManager 服务处理请求，检查本地模型或策略。
    6. 浏览器进程通过 Mojo 回调将结果 (例如 `CanCreateTranslatorResult::kReadily`) 发送回渲染进程。
    7. `canTranslate` 方法的回调函数根据 `CanCreateTranslatorResult` 的值，解析为 `V8TranslationAvailability` 枚举值 (例如 `kReadily`)。
    8. `ScriptPromiseResolver` 的 `Resolve` 方法被调用，将 `V8TranslationAvailability` 对象作为 Promise 的结果。

* **假设输出:** 一个 resolved 的 `ScriptPromise<V8TranslationAvailability>`，其结果值为一个 `V8TranslationAvailability` 对象，其 `value` 属性为 `'kReadily'` (如果英译法可以立即使用)。

假设 JavaScript 代码调用了 `createTranslator` 方法：

* **假设输入:**
    * `script_state`: 当前 JavaScript 的执行状态。
    * `options`: 一个 `TranslationLanguageOptions` 对象，包含 `sourceLanguage: "en"` 和 `targetLanguage: "de"`。
    * `exception_state`: 用于报告异常的状态对象。

* **逻辑推理:**
    1. `createTranslator` 方法被调用，检查 `script_state` 是否有效。
    2. 创建一个 `ScriptPromiseResolver` 和对应的 `ScriptPromise`。
    3. 创建一个 `CreateTranslatorClient` 对象，用于处理异步回调。
    4. 获取 `TranslationManagerRemote` 的远程接口。
    5. 调用 `translation_manager_remote_->CreateTranslator(client.BindNewPipeAndPassReceiver(), ...)`，向浏览器进程发送请求，创建英译德的翻译器。
    6. 浏览器进程的 TranslationManager 服务处理请求，加载模型并创建翻译器。
    7. 如果创建成功，浏览器进程通过 Mojo 回调 `CreateTranslatorClient::OnResult` 方法，传递创建的 `LanguageTranslator` 的 Mojo 接口。
    8. `CreateTranslatorClient::OnResult` 方法将接收到的 Mojo 接口包装成 `LanguageTranslator` 对象，并通过 `ScriptPromiseResolver` 的 `Resolve` 方法将该对象作为 Promise 的结果返回。
    9. 如果创建失败，浏览器进程通过 Mojo 回调 `CreateTranslatorClient::OnResult` 方法，传递错误信息。
    10. `CreateTranslatorClient::OnResult` 方法根据错误信息创建 `DOMException` 并通过 `ScriptPromiseResolver` 的 `Reject` 方法拒绝 Promise。

* **假设输出 (成功):** 一个 resolved 的 `ScriptPromise<LanguageTranslator>`，其结果值为一个 `LanguageTranslator` 对象。
* **假设输出 (失败):** 一个 rejected 的 `ScriptPromise<LanguageTranslator>`，其 reason 是一个 `DOMException` 对象。

**用户或编程常见的使用错误**

1. **传入不支持的语言代码:**  用户或开发者可能会尝试翻译或检测不支持的语言组合。这会导致 `canTranslate` 返回 `kNo` 或 `createTranslator` 抛出异常。

   **例子:**
   ```javascript
   navigator.ml.translation.createTranslator({ sourceLanguage: 'xx', targetLanguage: 'yy' })
     .catch(error => {
       // error.message 可能是 "Unable to create translator for the given source and target language."
     });
   ```

2. **在无效的执行上下文中使用 API:**  如果在页面加载完成之前或之后，当执行上下文不再有效时调用 API，会导致 `kInvalidStateError` 异常。

   **例子:**
   ```javascript
   // 假设在 document.addEventListener('DOMContentLoaded', ...) 外部调用
   navigator.ml.translation.canTranslate({ ... })
     .catch(error => {
       // error.name 可能是 "InvalidStateError"
     });
   ```

3. **频繁创建和销毁翻译器/检测器:**  虽然代码没有直接限制，但频繁地创建和销毁翻译器和检测器可能会带来性能开销。建议在需要时创建，并在不再使用时适当管理其生命周期。

4. **没有正确处理 Promise 的 rejection:**  开发者可能没有正确地使用 `.catch()` 来处理 `createTranslator` 或 `createDetector` 可能返回的 rejected promise，导致错误被忽略。

**用户操作是如何一步步的到达这里 (调试线索)**

以下是一个用户操作导致 `translation.cc` 中代码被执行的步骤示例（以网页上的一个翻译按钮为例）：

1. **用户访问网页:** 用户在 Chrome 浏览器中打开一个包含翻译功能的网页。
2. **网页加载和 JavaScript 执行:** 浏览器加载网页的 HTML、CSS 和 JavaScript 代码。
3. **JavaScript 添加事件监听器:** JavaScript 代码可能为页面上的一个“翻译”按钮添加了点击事件监听器。
4. **用户点击翻译按钮:** 用户点击了网页上的“翻译”按钮。
5. **事件监听器被触发:**  与按钮关联的 JavaScript 事件监听器函数被执行。
6. **调用 `navigator.ml.translation` API:**  事件监听器函数中调用了 `navigator.ml.translation.createTranslator({ sourceLanguage: 'en', targetLanguage: 'zh' })`  或类似的 API 来请求翻译。
7. **Blink 渲染引擎接收请求:**  浏览器将该 JavaScript API 调用传递给 Blink 渲染引擎中的相应模块。
8. **`Translation::createTranslator` 方法被调用:** `translation.cc` 文件中的 `Translation::createTranslator` 方法被调用，开始处理翻译请求。
9. **与浏览器进程通信:** `createTranslator` 方法通过 Mojo 向浏览器进程中的 TranslationManager 服务发送创建翻译器的请求。
10. **浏览器进程处理请求:** 浏览器进程的 TranslationManager 服务负责加载必要的翻译模型，创建翻译器实例。
11. **回调返回渲染进程:**  浏览器进程通过 Mojo 回调将创建的翻译器接口或错误信息返回给渲染进程的 `CreateTranslatorClient`。
12. **Promise resolved 或 rejected:** `CreateTranslatorClient` 根据回调结果，resolve 或 reject 相应的 JavaScript Promise。
13. **JavaScript 处理结果:**  网页上的 JavaScript 代码通过 `.then()` 或 `.catch()` 处理 Promise 的结果，并更新页面内容或显示错误信息。

**调试线索:**

* **断点:** 在 `translation.cc` 中相关的方法 (`canTranslate`, `createTranslator` 等) 设置断点，可以跟踪代码执行流程，查看参数和返回值。
* **Mojo 日志:**  查看 Chrome 的内部 Mojo 通信日志，可以了解渲染进程和浏览器进程之间交换的消息，帮助诊断通信问题。
* **JavaScript 控制台:**  查看 JavaScript 控制台的输出，包括 `console.log` 打印的信息和可能的错误信息。
* **网络面板:**  虽然设备端翻译不涉及网络请求，但在调试过程中，可以查看是否有其他相关的网络请求失败，这可能间接影响翻译功能。
* **`chrome://inspect/#devices`:** 使用 Chrome 的开发者工具检查页面，查看是否有与机器学习相关的错误或警告信息。

希望这个详细的分析能够帮助你理解 `translation.cc` 文件的功能和它在 Chromium 中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/on_device_translation/translation.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/on_device_translation/translation.h"

#include "base/metrics/histogram_functions.h"
#include "base/strings/strcat.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_translation_language_options.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/ai/ai_mojo_client.h"
#include "third_party/blink/renderer/modules/on_device_translation/language_detector.h"
#include "third_party/blink/renderer/modules/on_device_translation/language_translator.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver.h"

namespace blink {
namespace {

using mojom::blink::CreateTranslatorError;

const char kExceptionMessageUnableToCreateTranslator[] =
    "Unable to create translator for the given source and target language.";
const char kLinkToDocument[] =
    "See "
    "https://developer.chrome.com/docs/ai/translator-api?#supported-languages "
    "for more details.";

String ConvertCreateTranslatorErrorToDebugString(
    mojom::blink::CreateTranslatorError error) {
  switch (error) {
    case CreateTranslatorError::kInvalidBinary:
      return "Failed to load the translation library.";
    case CreateTranslatorError::kInvalidFunctionPointer:
      return "The translation library is not compatible.";
    case CreateTranslatorError::kFailedToInitialize:
      return "Failed to initialize the translation library.";
    case CreateTranslatorError::kFailedToCreateTranslator:
      return "The translation library failed to create a translator.";
    case CreateTranslatorError::kAcceptLanguagesCheckFailed:
      return String(base::StrCat(
          {"The preferred languages check for Translator API failed. ",
           kLinkToDocument}));
    case CreateTranslatorError::kExceedsLanguagePackCountLimitation:
      return String(base::StrCat(
          {"The Translator API language pack count exceeded the limitation. ",
           kLinkToDocument}));
    case CreateTranslatorError::kServiceCrashed:
      return "The translation service crashed.";
    case CreateTranslatorError::kDisallowedByPolicy:
      return "The translation is disallowed by policy.";
    case CreateTranslatorError::kExceedsServiceCountLimitation:
      return "The translation service count exceeded the limitation.";
    case CreateTranslatorError::kExceedsPendingTaskCountLimitation:
      return "Too many Translator API requests are queued.";
  }
}
class CreateTranslatorClient
    : public GarbageCollected<CreateTranslatorClient>,
      public mojom::blink::TranslationManagerCreateTranslatorClient,
      public AIMojoClient<LanguageTranslator> {
 public:
  CreateTranslatorClient(
      ScriptState* script_state,
      Translation* translation,
      scoped_refptr<base::SequencedTaskRunner> task_runner,
      ScriptPromiseResolver<LanguageTranslator>* resolver,
      String source_language,
      String target_language,
      mojo::PendingReceiver<
          mojom::blink::TranslationManagerCreateTranslatorClient>
          pending_receiver)
      : AIMojoClient(script_state,
                     translation,
                     resolver,
                     // Currently abort signal is not supported.
                     // TODO(crbug.com/331735396): Support abort signal.
                     /*abort_signal=*/nullptr),
        translation_(translation),
        receiver_(this, translation_->GetExecutionContext()),
        task_runner_(task_runner),
        source_language_(source_language),
        target_language_(target_language) {
    receiver_.Bind(std::move(pending_receiver), task_runner);
  }
  ~CreateTranslatorClient() override = default;

  CreateTranslatorClient(const CreateTranslatorClient&) = delete;
  CreateTranslatorClient& operator=(const CreateTranslatorClient&) = delete;

  void Trace(Visitor* visitor) const override {
    AIMojoClient::Trace(visitor);
    visitor->Trace(translation_);
    visitor->Trace(receiver_);
  }

  void OnResult(mojom::blink::CreateTranslatorResultPtr result) override {
    if (!GetResolver()) {
      // The request was aborted. Note: Currently abort signal is not supported.
      // TODO(crbug.com/331735396): Support abort signal.
      return;
    }
    if (result->is_translator()) {
      GetResolver()->Resolve(MakeGarbageCollected<LanguageTranslator>(
          source_language_, target_language_,
          std::move(result->get_translator()), task_runner_));
    } else {
      CHECK(result->is_error());
      translation_->GetExecutionContext()->AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kWarning,
          ConvertCreateTranslatorErrorToDebugString(result->get_error()));
      GetResolver()->Reject(DOMException::Create(
          kExceptionMessageUnableToCreateTranslator,
          DOMException::GetErrorName(DOMExceptionCode::kNotSupportedError)));
    }
    Cleanup();
  }

  void ResetReceiver() override {
    receiver_.reset();
  }

 private:
  Member<Translation> translation_;
  HeapMojoReceiver<mojom::blink::TranslationManagerCreateTranslatorClient,
                   CreateTranslatorClient>
      receiver_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  const String source_language_;
  const String target_language_;
};

}  // namespace

using mojom::blink::CanCreateTranslatorResult;

Translation::Translation(ExecutionContext* context)
    : ExecutionContextClient(context),
      task_runner_(context->GetTaskRunner(TaskType::kInternalDefault)) {}

void Translation::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  visitor->Trace(translation_manager_remote_);
}

HeapMojoRemote<mojom::blink::TranslationManager>&
Translation::GetTranslationManagerRemote() {
  if (!translation_manager_remote_.is_bound()) {
    if (GetExecutionContext()) {
      GetExecutionContext()->GetBrowserInterfaceBroker().GetInterface(
          translation_manager_remote_.BindNewPipeAndPassReceiver(task_runner_));
    }
  }
  return translation_manager_remote_;
}

// TODO(crbug.com/322229993): The new version is
// AITranslatorCapabilities::languagePairAvailable(). Delete this old version.
ScriptPromise<V8TranslationAvailability> Translation::canTranslate(
    ScriptState* script_state,
    TranslationLanguageOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    // TODO(https://crbug.com/357031848): Expose and use the helper.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The execution context is not valid.");
    return EmptyPromise();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8TranslationAvailability>>(
          script_state);
  auto promise = resolver->Promise();

  if (!GetTranslationManagerRemote().is_connected()) {
    resolver->Resolve(
        V8TranslationAvailability(V8TranslationAvailability::Enum::kNo));
  } else {
    GetTranslationManagerRemote()->CanCreateTranslator(
        options->sourceLanguage(), options->targetLanguage(),
        WTF::BindOnce(
            [](ScriptPromiseResolver<V8TranslationAvailability>* resolver,
               CanCreateTranslatorResult result) {
              // TODO(crbug.com/369761976): Record UMAs.
              switch (result) {
                case CanCreateTranslatorResult::kReadily:
                  resolver->Resolve(V8TranslationAvailability(
                      V8TranslationAvailability::Enum::kReadily));
                  break;
                case CanCreateTranslatorResult::kAfterDownloadLibraryNotReady:
                case CanCreateTranslatorResult::
                    kAfterDownloadLanguagePackNotReady:
                case CanCreateTranslatorResult::
                    kAfterDownloadLibraryAndLanguagePackNotReady:
                  resolver->Resolve(V8TranslationAvailability(
                      V8TranslationAvailability::Enum::kAfterDownload));
                  break;
                case CanCreateTranslatorResult::kNoNotSupportedLanguage:
                case CanCreateTranslatorResult::kNoAcceptLanguagesCheckFailed:
                case CanCreateTranslatorResult::
                    kNoExceedsLanguagePackCountLimitation:
                case CanCreateTranslatorResult::kNoServiceCrashed:
                case CanCreateTranslatorResult::kNoDisallowedByPolicy:
                case CanCreateTranslatorResult::
                    kNoExceedsServiceCountLimitation:
                  resolver->Resolve(V8TranslationAvailability(
                      V8TranslationAvailability::Enum::kNo));
                  break;
              }
            },
            WrapPersistent(resolver)));
  }

  return promise;
}

// TODO(crbug.com/349927087): The new version is
// AITranslatorFactory::create(). Delete this old version.
ScriptPromise<LanguageTranslator> Translation::createTranslator(
    ScriptState* script_state,
    TranslationLanguageOptions* options,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The execution context is not valid.");
    return EmptyPromise();
  }
  CHECK(options);
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<LanguageTranslator>>(
          script_state);
  auto promise = resolver->Promise();

  mojo::PendingRemote<mojom::blink::TranslationManagerCreateTranslatorClient>
      client;
  MakeGarbageCollected<CreateTranslatorClient>(
      script_state, this, task_runner_, resolver, options->sourceLanguage(),
      options->targetLanguage(), client.InitWithNewPipeAndPassReceiver());
  GetTranslationManagerRemote()->CreateTranslator(
      std::move(client),
      mojom::blink::TranslatorCreateOptions::New(options->sourceLanguage(),
                                                 options->targetLanguage()));
  return promise;
}

// TODO(crbug.com/349927087): The new version is
// AILanguageDetectorCapabilities::languageAvailable(). Delete this old version.
ScriptPromise<V8TranslationAvailability> Translation::canDetect(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The execution context is not valid.");
    return ScriptPromise<V8TranslationAvailability>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8TranslationAvailability>>(
          script_state);
  auto promise = resolver->Promise();

  resolver->Resolve(
      V8TranslationAvailability(V8TranslationAvailability::Enum::kReadily));

  return promise;
}

// TODO(crbug.com/349927087): The new version is
// AILanguageDetectorFactory::create(). Delete this old version.
ScriptPromise<LanguageDetector> Translation::createDetector(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The execution context is not valid.");
    return ScriptPromise<LanguageDetector>();
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<LanguageDetector>>(
          script_state);
  resolver->Resolve(MakeGarbageCollected<LanguageDetector>());
  return resolver->Promise();
}
}  // namespace blink

"""

```