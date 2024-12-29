Response:
Let's break down the thought process for analyzing the `font_resource.cc` file.

**1. Initial Understanding of the File's Purpose:**

The file name `font_resource.cc` within the `blink/renderer/core/loader/resource/` directory strongly suggests this file is responsible for handling font resources within the Blink rendering engine. The `Resource` part of the name indicates it's likely a subclass or related to a more general resource loading mechanism.

**2. Core Functionality Identification (Scanning the Code):**

I'll start skimming the code, looking for key classes, methods, and data structures.

* **`FontResource` class:** This is the central class. Its methods and members will reveal the core functionalities.
* **`BackgroundFontProcessor` and `BackgroundFontProcessorFactory`:** These names suggest asynchronous processing of font data, likely for decoding.
* **`DecodeFont` function:** Clearly involved in the actual font decoding.
* **`FontCustomPlatformData`:**  This likely holds the decoded font data in a platform-specific format.
* **`WebFontDecoder`:**  The component responsible for the decoding process itself.
* **`FontResourceClient`:**  An interface for clients that need to be notified about font loading status.
* **Methods like `Fetch`, `DidAddClient`, `StartLoadLimitTimersIfNecessary`, `GetCustomFontData`, `NotifyFinished`:** These indicate the lifecycle management and interaction with other parts of the engine.
* **Time-related constants (`kFontLoadWaitShort`, `kFontLoadWaitLong`) and associated logic (`font_load_short_limit_`, `font_load_long_limit_`):** This points to handling font-display related timing.

**3. Relationship to JavaScript, HTML, and CSS:**

Now, I connect the identified functionalities to the front-end web technologies:

* **CSS `@font-face`:** This is the primary way fonts are declared in CSS. The `FontResource` is directly responsible for fetching and processing the font files referenced in `@font-face` rules.
* **`font-display` CSS property:** The `kFontLoadWaitShort` and `kFontLoadWaitLong` constants, along with the `FontLoadShortLimitCallback` and `FontLoadLongLimitCallback` methods, directly correspond to the `font-display` property's behavior (block, swap, fallback, optional, auto).
* **JavaScript font loading API (e.g., `FontFace`):** While not explicitly mentioned in *this specific file*, it's highly probable that this `FontResource` is used by the underlying implementation of the JavaScript Font Loading API.
* **HTML text rendering:** Ultimately, the decoded font data (`FontCustomPlatformData`) is used by the rendering engine to draw text on the screen.

**4. Logic Reasoning (Hypothetical Input/Output):**

I'll consider a simplified scenario:

* **Input:** A CSS rule like `@font-face { font-family: 'MyFont'; src: url('myfont.woff2'); font-display: swap; }`.
* **Process:**
    1. The browser parses the CSS and identifies the need for the font resource.
    2. A `FontResource` object is created for `myfont.woff2`.
    3. The resource is fetched.
    4. `BackgroundFontProcessor` decodes the font data.
    5. The decoded font data is stored in `FontCustomPlatformData`.
    6. If `font-display: swap` is set, initially, system fonts might be used. After a short delay (`kFontLoadWaitShort`), if the font isn't loaded,  the browser might still use system fonts. After a longer delay (`kFontLoadWaitLong`), the browser will try to use the loaded font (if successful) or continue with fallback fonts.
* **Output:** The text on the webpage is rendered using "MyFont" once it's successfully loaded. If loading takes too long, fallback fonts might be displayed temporarily.

**5. Common Usage Errors:**

I'll think about common mistakes developers make related to fonts:

* **Incorrect font file path:** This will lead to a failed resource load.
* **Unsupported font format:** The browser might not be able to decode the font. The `DecodeFont` function handles this.
* **CORS issues:**  Loading fonts from a different origin requires proper CORS headers. The `cors_failed_` member suggests handling of this.
* **Large font files:**  Can lead to delays in rendering, impacting user experience. The load limit timers are designed to address this.

**6. Debugging Clues and User Actions:**

I'll trace back how a developer might end up investigating this file:

* **Problem:**  Fonts aren't loading correctly, or there's a delay in font rendering.
* **Debugging Steps:**
    1. Open browser developer tools.
    2. Check the "Network" tab to see if the font file was loaded successfully and its status code.
    3. Look for console errors related to font loading or CORS.
    4. If the network request seems fine, but the font isn't being applied, the developer might suspect a decoding issue.
    5. They might then search the Chromium source code for "FontResource" or "WebFontDecoder" to understand the font loading process.
    6. This could lead them to `font_resource.cc` to investigate how font data is fetched, decoded, and managed.

**7. Refinement and Organization:**

Finally, I organize the information logically, using clear headings and bullet points. I make sure to include specific examples and connect the technical details to the user-facing aspects of web development. I also ensure I address all the specific prompts in the original request.
好的，让我们详细分析一下 `blink/renderer/core/loader/resource/font_resource.cc` 这个文件。

**文件功能概述:**

`font_resource.cc` 文件是 Chromium Blink 渲染引擎中负责处理 **字体资源** 的核心组件。它的主要功能包括：

1. **字体资源的加载和管理:**  负责发起、跟踪和管理字体文件的网络请求和加载过程。
2. **字体数据的解码:**  接收到字体数据后，调用解码器将字体文件（如 TTF, OTF, WOFF, WOFF2）解码成浏览器可以使用的内部格式。
3. **`font-display` 的实现:**  实现了 CSS `font-display` 属性的逻辑，控制字体加载的不同阶段的行为，例如初始阻塞时间、交换时间等。
4. **字体加载限制:**  设置字体加载的时间限制，如果超过限制，会通知客户端（通常是渲染引擎的其他部分）。
5. **提供解码后的字体数据:**  将解码后的字体数据提供给渲染引擎，用于文本的绘制。
6. **内存管理:**  负责管理解码后的字体数据占用的内存。
7. **与缓存的交互:**  处理字体资源的缓存，包括从缓存加载和将新加载的字体缓存起来。
8. **后台解码:**  将耗时的字体解码操作放在后台线程执行，避免阻塞主线程。
9. **CORS 处理:**  处理跨域字体加载可能出现的 CORS (Cross-Origin Resource Sharing) 问题。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`font_resource.cc` 直接关联着 Web 开发中的 CSS 和 JavaScript 字体相关的特性：

* **CSS `@font-face` 规则:**  当浏览器解析到 CSS 中的 `@font-face` 规则时，会创建一个 `FontResource` 对象来加载 `src` 属性指定的字体文件。
    * **举例:**  在 CSS 文件中有如下代码：
      ```css
      @font-face {
        font-family: 'MyCustomFont';
        src: url('fonts/myfont.woff2') format('woff2');
        font-display: swap;
      }

      body {
        font-family: 'MyCustomFont', sans-serif;
      }
      ```
      当浏览器遇到这个 CSS 时，`font_resource.cc` 中的代码会负责加载 `fonts/myfont.woff2` 文件。`font-display: swap;` 也会被 `FontResource` 处理，控制字体加载期间的渲染行为。

* **CSS `font-display` 属性:** `FontResource` 实现了 `font-display` 的 `auto`, `block`, `swap`, `fallback`, `optional` 等值对应的行为。
    * **举例:**  如果 `font-display` 设置为 `block`，那么在字体加载完成前，使用该字体的文本可能会不可见或者显示为占位符。`FontResource` 会维护加载状态，并在加载完成后通知渲染引擎进行重绘。
    * **举例:**  如果 `font-display` 设置为 `swap`，浏览器会先用后备字体显示文本，当自定义字体加载完成后再切换为自定义字体。`FontResource` 中的定时器和回调函数会参与到这个切换过程中。

* **JavaScript Font Loading API (`FontFace`):** JavaScript 可以通过 `FontFace` 接口动态地加载和使用字体。`FontResource` 作为底层的实现，会被 JavaScript Font Loading API 调用，处理字体的加载和解码。
    * **举例:**  JavaScript 代码如下：
      ```javascript
      const font = new FontFace('MyDynamicFont', 'url(fonts/dynamic.woff2)');
      document.fonts.add(font);
      font.load().then(() => {
        document.body.style.fontFamily = 'MyDynamicFont';
      });
      ```
      在这个例子中，`font.load()` 的执行会触发 `FontResource` 加载 `fonts/dynamic.woff2` 文件。

**逻辑推理 (假设输入与输出):**

假设用户在 CSS 中使用了 `@font-face` 定义了一个字体，并且设置了 `font-display: swap;`。

* **假设输入:**
    * CSS 规则: `@font-face { font-family: 'TestFont'; src: url('test.woff2'); font-display: swap; }`
    * HTML 中有元素使用了 `font-family: 'TestFont';`
    * `test.woff2` 文件较大，加载需要一定时间。

* **处理过程 (`FontResource` 相关的部分):**
    1. 当解析到 CSS 规则时，创建一个 `FontResource` 对象，请求加载 `test.woff2`。
    2. `FontResource` 启动加载限制定时器 (`kFontLoadWaitShort`, `kFontLoadWaitLong`)。
    3. 在初始的短时间内 (`kFontLoadWaitShort`)，如果字体未加载完成，客户端会收到通知，可能仍然使用后备字体渲染。
    4. 如果在较长的时间内 (`kFontLoadWaitLong`) 字体仍未加载完成，客户端会再次收到通知。
    5. 当 `test.woff2` 的数据加载完成后，`FontResource` 将数据传递给后台字体处理器 (`BackgroundFontProcessor`) 进行解码。
    6. 解码完成后，`FontResource` 收到解码结果，并通知客户端。
    7. 客户端（渲染引擎）收到通知后，会使用解码后的字体重新渲染使用了 `'TestFont'` 的文本。

* **假设输出:**
    * 页面初始渲染时，使用了后备字体显示文本。
    * 一段时间后（字体加载并解码完成后），文本的字体切换为 'TestFont'。

**用户或编程常见的使用错误:**

1. **错误的字体文件路径:**  如果在 `@font-face` 的 `src` 中指定了不存在或路径错误的字体文件，`FontResource` 会加载失败，导致字体无法应用。
    * **例子:**  `src: url('font/myfont.woff2');` 但实际文件在 `fonts/myfont.woff2`。
    * **调试线索:**  开发者工具的 "Network" 标签会显示该字体请求失败 (通常是 404 错误)。

2. **CORS 配置错误:**  如果字体文件托管在不同的域名下，服务器没有配置正确的 CORS 头信息 (例如 `Access-Control-Allow-Origin`)，浏览器会阻止跨域字体加载。
    * **例子:**  字体文件在 `cdn.example.com`，而网页在 `www.mywebsite.com`。 `cdn.example.com` 需要设置允许 `www.mywebsite.com` 访问的 CORS 头。
    * **调试线索:**  浏览器控制台会显示 CORS 相关的错误信息，提示跨域请求被阻止。 `FontResource` 中的 `cors_failed_` 标志可能会被设置。

3. **不支持的字体格式:**  浏览器可能不支持某些字体格式。虽然现代浏览器对常见格式支持较好，但如果使用了非常老的格式，可能会出现问题。
    * **例子:**  只提供了 SVG 字体，而目标浏览器不支持。
    * **调试线索:**  虽然资源可能加载成功，但解码过程会失败。 `FontResource::GetCustomFontData()` 可能会返回空，并设置 `ResourceStatus::kDecodeError`。

4. **字体文件损坏:**  如果下载的字体文件本身损坏，解码过程会失败。
    * **调试线索:**  类似于不支持的字体格式，解码会失败。

5. **`font-display` 理解错误:**  开发者可能对 `font-display` 的行为理解有误，导致预期之外的字体加载和渲染效果。
    * **例子:**  认为 `font-display: block;` 会立即显示文本，但实际上在阻塞期间可能会看不到文本。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网页:**  这是所有事情的起点。
2. **浏览器解析 HTML 和 CSS:**  当浏览器解析到使用了自定义字体的 CSS 规则时，会触发字体资源的加载。
3. **创建 `FontResource` 对象:**  Blink 渲染引擎会为每个需要加载的字体创建一个 `FontResource` 对象。
4. **发起网络请求:**  `FontResource` 对象会根据 `@font-face` 规则中的 `src` 发起网络请求，下载字体文件。
5. **接收网络响应:**  网络层接收到字体文件的数据。
6. **数据传递给 `FontResource`:**  下载的数据被传递给对应的 `FontResource` 对象。
7. **后台解码 (可选):**  `FontResource` 可能将解码任务交给后台线程的 `BackgroundFontProcessor` 处理。
8. **解码完成:**  字体解码器将字体数据解码成可用的格式。
9. **通知客户端:**  `FontResource` 通知渲染引擎的客户端，字体加载和解码已完成。
10. **使用字体进行渲染:**  渲染引擎使用解码后的字体数据来绘制文本。

**调试线索:**

如果开发者遇到字体加载问题，可以按照以下步骤进行调试，这些步骤会涉及到 `font_resource.cc` 相关的逻辑：

1. **检查开发者工具的 "Network" 标签:**  查看字体文件的请求状态，是否成功加载，是否有 CORS 错误。
2. **检查开发者工具的 "Console" 标签:**  查看是否有与字体加载相关的错误信息。
3. **使用 "Application" 或 "Sources" 标签检查缓存:**  查看字体是否被缓存，以及缓存策略是否正确。
4. **使用 "Performance" 标签进行性能分析:**  查看字体加载和渲染对页面性能的影响。
5. **在 Chromium 源码中搜索关键信息:**  如果需要深入了解细节，可以搜索 `font_resource.cc` 中的相关日志输出或断点，跟踪代码执行流程。例如，可以搜索 "FontLoadShortLimitExceeded" 或 "DecodeFont" 等关键字符串。

希望以上分析能够帮助你理解 `blink/renderer/core/loader/resource/font_resource.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/loader/resource/font_resource.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2009 Torch Mobile, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/loader/resource/font_resource.h"

#include <utility>

#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/types/expected.h"
#include "build/build_config.h"
#include "mojo/public/cpp/system/data_pipe_drainer.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/renderer/platform/fonts/font_custom_platform_data.h"
#include "third_party/blink/renderer/platform/fonts/font_platform_data.h"
#include "third_party/blink/renderer/platform/fonts/web_font_decoder.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_client_walker.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

#if BUILDFLAG(IS_WIN)
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#endif  // IS_WIN

using ResultOrError =
    base::expected<blink::FontResource::DecodedResult, String>;

namespace WTF {

template <>
struct CrossThreadCopier<ResultOrError> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = ResultOrError;
  static Type Copy(Type&& value) { return std::move(value); }
};

}  // namespace WTF

namespace blink {

namespace {
// Durations of font-display periods.
// https://tabatkins.github.io/specs/css-font-display/#font-display-desc
// TODO(toyoshim): Revisit short limit value once cache-aware font display is
// launched. crbug.com/570205
constexpr base::TimeDelta kFontLoadWaitShort = base::Milliseconds(100);
constexpr base::TimeDelta kFontLoadWaitLong = base::Milliseconds(3000);

base::expected<FontResource::DecodedResult, String> DecodeFont(
    SegmentedBuffer* buffer) {
  if (buffer->empty()) {
    // We don't have any data to decode. Just return an empty error string.
    return base::unexpected("");
  }
  WebFontDecoder decoder;
  auto decode_start_time = base::TimeTicks::Now();
  sk_sp<SkTypeface> typeface = decoder.Decode(buffer);
  base::UmaHistogramMicrosecondsTimes(
      "Blink.Fonts.BackgroundDecodeTime",
      base::TimeTicks::Now() - decode_start_time);
  if (typeface) {
    return FontResource::DecodedResult(std::move(typeface),
                                       decoder.DecodedSize());
  }
  return base::unexpected(decoder.GetErrorString());
}

scoped_refptr<base::SequencedTaskRunner> GetFontDecodingTaskRunner() {
#if BUILDFLAG(IS_WIN)
  // On Windows, the font decoding relies on FontManager, which requires
  // creating garbage collected objects. This means the thread the decoding
  // runs on must be GC enabled.
  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      std::unique_ptr<NonMainThread>, font_decoding_thread,
      (NonMainThread::CreateThread(
          ThreadCreationParams(ThreadType::kFontThread).SetSupportsGC(true))));
  return font_decoding_thread->GetTaskRunner();
#else
  return worker_pool::CreateSequencedTaskRunner(
      {base::TaskPriority::USER_BLOCKING});
#endif  // IS_WIN
}

}  // namespace

class FontResource::BackgroundFontProcessor final
    : public BackgroundResponseProcessor,
      public mojo::DataPipeDrainer::Client {
 public:
  explicit BackgroundFontProcessor(
      CrossThreadWeakHandle<FontResource> resource_handle);
  ~BackgroundFontProcessor() override;

  BackgroundFontProcessor(const BackgroundFontProcessor&) = delete;
  BackgroundFontProcessor& operator=(const BackgroundFontProcessor&) = delete;

  // Implements BackgroundResponseProcessor interface.
  bool MaybeStartProcessingResponse(
      network::mojom::URLResponseHeadPtr& head,
      mojo::ScopedDataPipeConsumerHandle& body,
      std::optional<mojo_base::BigBuffer>& cached_metadata_buffer,
      scoped_refptr<base::SequencedTaskRunner> background_task_runner,
      BackgroundResponseProcessor::Client* client) override;

  // Implements mojo::DataPipeDrainer::Client interface.
  void OnDataAvailable(base::span<const uint8_t> data) override;
  void OnDataComplete() override;

 private:
  static void DecodeOnBackgroundThread(
      SegmentedBuffer data,
      scoped_refptr<base::SequencedTaskRunner> background_task_runner,
      base::WeakPtr<BackgroundFontProcessor> weak_this);

  void OnDecodeComplete(ResultOrError result_or_error, SegmentedBuffer data);

  network::mojom::URLResponseHeadPtr head_;
  std::optional<mojo_base::BigBuffer> cached_metadata_buffer_;
  scoped_refptr<base::SequencedTaskRunner> background_task_runner_;
  BackgroundResponseProcessor::Client* client_;

  std::unique_ptr<mojo::DataPipeDrainer> pipe_drainer_;
  SegmentedBuffer buffer_;
  CrossThreadWeakHandle<FontResource> resource_handle_;
  base::WeakPtrFactory<BackgroundFontProcessor> weak_factory_{this};
};

class FontResource::BackgroundFontProcessorFactory
    : public BackgroundResponseProcessorFactory {
 public:
  explicit BackgroundFontProcessorFactory(
      CrossThreadWeakHandle<FontResource> resource_handle);
  ~BackgroundFontProcessorFactory() override;
  BackgroundFontProcessorFactory(const BackgroundFontProcessorFactory&) =
      delete;
  BackgroundFontProcessorFactory& operator=(
      const BackgroundFontProcessorFactory&) = delete;
  std::unique_ptr<BackgroundResponseProcessor> Create() && override;

 private:
  CrossThreadWeakHandle<FontResource> resource_handle_;
};

FontResource::BackgroundFontProcessor::BackgroundFontProcessor(
    CrossThreadWeakHandle<FontResource> resource_handle)
    : resource_handle_(std::move(resource_handle)) {}

FontResource::BackgroundFontProcessor::~BackgroundFontProcessor() = default;

bool FontResource::BackgroundFontProcessor::MaybeStartProcessingResponse(
    network::mojom::URLResponseHeadPtr& head,
    mojo::ScopedDataPipeConsumerHandle& body,
    std::optional<mojo_base::BigBuffer>& cached_metadata_buffer,
    scoped_refptr<base::SequencedTaskRunner> background_task_runner,
    BackgroundResponseProcessor::Client* client) {
  head_ = std::move(head);
  cached_metadata_buffer_ = std::move(cached_metadata_buffer);
  background_task_runner_ = background_task_runner;
  client_ = client;
  pipe_drainer_ =
      std::make_unique<mojo::DataPipeDrainer>(this, std::move(body));
  return true;
}

void FontResource::BackgroundFontProcessor::OnDataAvailable(
    base::span<const uint8_t> data) {
  buffer_.Append(Vector<char>(data));
}

void FontResource::BackgroundFontProcessor::OnDataComplete() {
  PostCrossThreadTask(
      *GetFontDecodingTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(
          &FontResource::BackgroundFontProcessor::DecodeOnBackgroundThread,
          std::move(buffer_), background_task_runner_,
          weak_factory_.GetWeakPtr()));
}

// static
void FontResource::BackgroundFontProcessor::DecodeOnBackgroundThread(
    SegmentedBuffer data,
    scoped_refptr<base::SequencedTaskRunner> background_task_runner,
    base::WeakPtr<BackgroundFontProcessor> weak_this) {
  base::expected<DecodedResult, String> result_or_error = DecodeFont(&data);
  PostCrossThreadTask(
      *background_task_runner, FROM_HERE,
      CrossThreadBindOnce(
          &FontResource::BackgroundFontProcessor::OnDecodeComplete,
          std::move(weak_this), std::move(result_or_error), std::move(data)));
}

void FontResource::BackgroundFontProcessor::OnDecodeComplete(
    base::expected<DecodedResult, String> result_or_error,
    SegmentedBuffer data) {
  DCHECK(background_task_runner_->RunsTasksInCurrentSequence());
  client_->PostTaskToMainThread(CrossThreadBindOnce(
      &FontResource::OnBackgroundDecodeFinished,
      MakeUnwrappingCrossThreadWeakHandle(std::move(resource_handle_)),
      std::move(result_or_error)));
  client_->DidFinishBackgroundResponseProcessor(
      std::move(head_), std::move(data), std::move(cached_metadata_buffer_));
}

FontResource::BackgroundFontProcessorFactory::BackgroundFontProcessorFactory(
    CrossThreadWeakHandle<FontResource> resource_handle)
    : resource_handle_(resource_handle) {}

FontResource::BackgroundFontProcessorFactory::
    ~BackgroundFontProcessorFactory() = default;

std::unique_ptr<BackgroundResponseProcessor>
FontResource::BackgroundFontProcessorFactory::Create() && {
  return std::make_unique<BackgroundFontProcessor>(std::move(resource_handle_));
}

FontResource* FontResource::Fetch(FetchParameters& params,
                                  ResourceFetcher* fetcher,
                                  FontResourceClient* client) {
  params.SetRequestContext(mojom::blink::RequestContextType::FONT);
  params.SetRequestDestination(network::mojom::RequestDestination::kFont);
  return To<FontResource>(
      fetcher->RequestResource(params, FontResourceFactory(), client));
}

FontResource::FontResource(const ResourceRequest& resource_request,
                           const ResourceLoaderOptions& options)
    : Resource(resource_request, ResourceType::kFont, options),
      load_limit_state_(LoadLimitState::kLoadNotStarted),
      cors_failed_(false) {}

FontResource::~FontResource() = default;

void FontResource::DidAddClient(ResourceClient* c) {
  DCHECK(c->IsFontResourceClient());
  Resource::DidAddClient(c);

  // Block client callbacks if currently loading from cache.
  if (IsLoading() && Loader()->IsCacheAwareLoadingActivated())
    return;

  ProhibitAddRemoveClientInScope prohibit_add_remove_client(this);
  if (load_limit_state_ == LoadLimitState::kShortLimitExceeded ||
      load_limit_state_ == LoadLimitState::kLongLimitExceeded)
    static_cast<FontResourceClient*>(c)->FontLoadShortLimitExceeded(this);
  if (load_limit_state_ == LoadLimitState::kLongLimitExceeded)
    static_cast<FontResourceClient*>(c)->FontLoadLongLimitExceeded(this);
}

void FontResource::SetRevalidatingRequest(const ResourceRequestHead& request) {
  // Reload will use the same object, and needs to reset |m_loadLimitState|
  // before any didAddClient() is called again.
  DCHECK(IsLoaded());
  DCHECK(!font_load_short_limit_.IsActive());
  DCHECK(!font_load_long_limit_.IsActive());
  load_limit_state_ = LoadLimitState::kLoadNotStarted;
  Resource::SetRevalidatingRequest(request);
}

void FontResource::StartLoadLimitTimersIfNecessary(
    base::SingleThreadTaskRunner* task_runner) {
  if (!IsLoading() || load_limit_state_ != LoadLimitState::kLoadNotStarted)
    return;
  DCHECK(!font_load_short_limit_.IsActive());
  DCHECK(!font_load_long_limit_.IsActive());
  load_limit_state_ = LoadLimitState::kUnderLimit;

  font_load_short_limit_ = PostDelayedCancellableTask(
      *task_runner, FROM_HERE,
      WTF::BindOnce(&FontResource::FontLoadShortLimitCallback,
                    WrapWeakPersistent(this)),
      kFontLoadWaitShort);
  font_load_long_limit_ = PostDelayedCancellableTask(
      *task_runner, FROM_HERE,
      WTF::BindOnce(&FontResource::FontLoadLongLimitCallback,
                    WrapWeakPersistent(this)),
      kFontLoadWaitLong);
}

const FontCustomPlatformData* FontResource::GetCustomFontData() {
  if (font_data_ || ErrorOccurred() || IsLoading()) {
    return font_data_;
  }
  if (Data()) {
    if (background_decode_result_or_error_) {
      if (background_decode_result_or_error_->has_value()) {
        font_data_ = FontCustomPlatformData::Create(
            std::move((*background_decode_result_or_error_)->sk_typeface),
            (*background_decode_result_or_error_)->decoded_size);
      } else {
        ots_parsing_message_ = background_decode_result_or_error_->error();
      }
    } else {
      auto decode_start_time = base::TimeTicks::Now();
      font_data_ = FontCustomPlatformData::Create(Data(), ots_parsing_message_);
      base::UmaHistogramMicrosecondsTimes(
          "Blink.Fonts.DecodeTime", base::TimeTicks::Now() - decode_start_time);
    }
  }

  if (!font_data_) {
    SetStatus(ResourceStatus::kDecodeError);
  } else {
    // Call observers once and remove them.
    HeapHashSet<WeakMember<FontResourceClearDataObserver>> observers;
    observers.swap(clear_data_observers_);
    for (const auto& observer : observers) {
      observer->FontResourceDataWillBeCleared();
    }
    ClearData();
  }
  return font_data_;
}

void FontResource::WillReloadAfterDiskCacheMiss() {
  DCHECK(IsLoading());
  DCHECK(Loader()->IsCacheAwareLoadingActivated());
  if (load_limit_state_ == LoadLimitState::kShortLimitExceeded ||
      load_limit_state_ == LoadLimitState::kLongLimitExceeded) {
    NotifyClientsShortLimitExceeded();
  }
  if (load_limit_state_ == LoadLimitState::kLongLimitExceeded)
    NotifyClientsLongLimitExceeded();
}

void FontResource::FontLoadShortLimitCallback() {
  DCHECK(IsLoading());
  DCHECK_EQ(load_limit_state_, LoadLimitState::kUnderLimit);
  load_limit_state_ = LoadLimitState::kShortLimitExceeded;

  // Block client callbacks if currently loading from cache.
  if (Loader()->IsCacheAwareLoadingActivated())
    return;
  NotifyClientsShortLimitExceeded();
}

void FontResource::FontLoadLongLimitCallback() {
  DCHECK(IsLoading());
  DCHECK_EQ(load_limit_state_, LoadLimitState::kShortLimitExceeded);
  load_limit_state_ = LoadLimitState::kLongLimitExceeded;

  // Block client callbacks if currently loading from cache.
  if (Loader()->IsCacheAwareLoadingActivated())
    return;
  NotifyClientsLongLimitExceeded();
}

void FontResource::NotifyClientsShortLimitExceeded() {
  ProhibitAddRemoveClientInScope prohibit_add_remove_client(this);
  ResourceClientWalker<FontResourceClient> walker(Clients());
  while (FontResourceClient* client = walker.Next())
    client->FontLoadShortLimitExceeded(this);
}

void FontResource::NotifyClientsLongLimitExceeded() {
  ProhibitAddRemoveClientInScope prohibit_add_remove_client(this);
  ResourceClientWalker<FontResourceClient> walker(Clients());
  while (FontResourceClient* client = walker.Next())
    client->FontLoadLongLimitExceeded(this);
}

void FontResource::NotifyFinished() {
  font_load_short_limit_.Cancel();
  font_load_long_limit_.Cancel();

  Resource::NotifyFinished();
}

bool FontResource::IsLowPriorityLoadingAllowedForRemoteFont() const {
  DCHECK(!IsLoaded());
  if (Url().ProtocolIsData())
    return false;
  ResourceClientWalker<FontResourceClient> walker(Clients());
  while (FontResourceClient* client = walker.Next()) {
    if (!client->IsLowPriorityLoadingAllowedForRemoteFont()) {
      return false;
    }
  }
  return true;
}

void FontResource::OnMemoryDump(WebMemoryDumpLevelOfDetail level,
                                WebProcessMemoryDump* memory_dump) const {
  Resource::OnMemoryDump(level, memory_dump);
  if (!font_data_)
    return;
  const String name = GetMemoryDumpName() + "/decoded_webfont";
  WebMemoryAllocatorDump* dump = memory_dump->CreateMemoryAllocatorDump(name);
  dump->AddScalar("size", "bytes", font_data_->DataSize());

  const char* system_allocator_name =
      base::trace_event::MemoryDumpManager::GetInstance()
          ->system_allocator_pool_name();
  if (system_allocator_name) {
    memory_dump->AddSuballocation(dump->Guid(), system_allocator_name);
  }
}

void FontResource::AddClearDataObserver(
    FontResourceClearDataObserver* observer) const {
  clear_data_observers_.insert(observer);
}

std::unique_ptr<BackgroundResponseProcessorFactory>
FontResource::MaybeCreateBackgroundResponseProcessorFactory() {
  if (!features::kBackgroundFontResponseProcessor.Get()) {
    return nullptr;
  }
  return std::make_unique<BackgroundFontProcessorFactory>(
      MakeCrossThreadWeakHandle(this));
}

void FontResource::OnBackgroundDecodeFinished(
    base::expected<DecodedResult, String> result_or_error) {
  background_decode_result_or_error_ = std::move(result_or_error);
}

void FontResource::Trace(Visitor* visitor) const {
  visitor->Trace(font_data_);
  visitor->Trace(clear_data_observers_);
  Resource::Trace(visitor);
}

}  // namespace blink

"""

```