Response:
Let's break down the thought process for analyzing the provided C++ test file for the Web Share API in Chromium.

**1. Initial Scan and Purpose Identification:**

The first thing I'd do is scan the `#include` directives and the class name `NavigatorShareTest`. The includes point to things like `gtest` (for testing), various Blink platform components (`platform/`, `core/`), and specifically `third_party/blink/renderer/modules/webshare/navigator_share.h`. The class name `NavigatorShareTest` strongly suggests this is a test file for the `NavigatorShare` functionality. The comments at the top confirm this is a test for the Web Share API.

**2. Understanding the Test Structure (GTest):**

I recognize the `TEST_F` macro, which is a standard GTest construct for defining test cases within a fixture (`NavigatorShareTest`). This tells me each `TEST_F` block represents an individual test scenario.

**3. Analyzing the Test Fixture (`NavigatorShareTest`):**

* **Setup and Teardown:** I immediately look for `SetUp()` and `TearDown()` methods. These are common in testing to prepare the environment before each test and clean up afterward.
    * `SetUp()` initializes a dummy page, commits a navigation, and importantly, sets up a mock `ShareService`. This is a crucial part – it intercepts the real system's sharing mechanism.
    * `TearDown()` removes the mock binder and clears the memory cache. This avoids interference between tests.
* **Helper Functions:**  I notice `GetDocument()`, `GetFrame()`, `GetScriptState()`. These provide easy access to core Blink objects needed for testing.
* **`Share()` method:** This is a key method. It simulates a JavaScript call to `navigator.share()`. It takes `ShareData`, triggers user activation (important for security), calls `NavigatorShare::share`, runs pending tasks (to let asynchronous operations complete), and checks if the promise was fulfilled or rejected based on the mock service's error status.
* **`mock_share_service()`:** This provides access to the mock object, allowing the tests to inspect what the `NavigatorShare` code tried to do.
* **Member Variables:**  The presence of `mock_share_service_`, `holder_`, `handle_scope_`, `context_`, `context_scope_`, and `task_environment` confirms this is a controlled testing environment.

**4. Deconstructing the `MockShareService`:**

This is critical to understanding how the tests work.

* **Purpose:** The comment clearly states it's used to intercept calls to the Mojo methods. This means instead of actually sharing, the test can examine the data passed to the (mock) sharing service.
* **`Share()` method:**  This overridden `Share` method *doesn't* actually perform a share. Instead, it captures the `title`, `text`, `url`, and `files` parameters. This is the core of how the tests verify what data is being sent. It also has a `set_error()` method to simulate different sharing outcomes (success or cancellation).

**5. Analyzing Individual Test Cases:**

Now I go through each `TEST_F` block:

* **`ShareText`:**  Creates `ShareData` with text, title, and URL. Calls `Share()`. Then, it asserts that the `mock_share_service()` received the correct values and that relevant UseCounters were incremented (indicating features were used).
* **`ShareFile`:** Creates a sample file using `CreateSampleFile`. Sets the `files` on `ShareData`. Calls `Share()`. Asserts that the mock service received the file with the correct name, type, and size, and checks for file-related UseCounters.
* **`CancelShare`:** Sets the mock service to return a "canceled" error. Calls `Share()` with title data. Verifies that the promise was rejected and checks for "unsuccessful" UseCounters.
* **`CancelShareWithFile`:**  Similar to `CancelShare`, but includes a file in the `ShareData`. Verifies rejection and the appropriate "unsuccessful" UseCounters for file sharing.

**6. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now I start thinking about how this C++ test relates to the front-end:

* **JavaScript API:** The `NavigatorShare::share()` call in the `Share()` helper directly corresponds to the `navigator.share()` JavaScript API. The `ShareData` object maps to the dictionary passed to `navigator.share()`.
* **HTML (Indirect):** The tests create a dummy page, which inherently involves HTML. The origin of the page ("https://example.com") is set, which is relevant for security considerations of the Web Share API.
* **CSS (Unlikely):**  The focus of this test is on the core functionality of the sharing mechanism, not the visual presentation. CSS is unlikely to be directly involved.

**7. Logical Reasoning (Assumptions and Outputs):**

For each test case, I can infer the intended input and expected output:

* **Input:**  Specific `ShareData` (text, URL, files) and the configured error status of the `MockShareService`.
* **Output:** The state of the promise (fulfilled or rejected) and the data captured by the `MockShareService`. The incrementing of specific UseCounters is also an output to observe.

**8. Identifying Potential User/Programming Errors:**

I consider common mistakes developers might make when using the Web Share API:

* Not handling promise rejections.
* Incorrectly constructing the `ShareData` object (e.g., providing invalid URLs or file types).
* Trying to share too many or too large files. (Though these specific tests don't explicitly cover those limits, the underlying API has them).
* Forgetting user activation, which is enforced by the `LocalFrame::NotifyUserActivation` call in the test.

**9. Tracing User Operations (Debugging Clues):**

I think about how a user's action might lead to this code being executed:

1. **User Interaction:** The user clicks a "Share" button on a webpage.
2. **JavaScript Execution:** The button's click handler calls `navigator.share({...})`.
3. **Browser Processing:** The browser receives this JavaScript call.
4. **Blink Implementation:** The Blink rendering engine's JavaScript implementation of `navigator.share()` calls the native C++ code in `blink/renderer/modules/webshare/navigator_share.cc`.
5. **Mojo Communication:** `NavigatorShare::share()` interacts with the browser process (outside of Blink) via Mojo to initiate the actual sharing. This is where the `MockShareService` in the tests comes in, simulating this browser-side component.

By following these steps, I could arrive at a comprehensive understanding of the test file's purpose, its relationship to web technologies, and how it fits into the overall Web Share API implementation in Chromium.
这个C++文件 `navigator_share_test.cc` 是 Chromium Blink 引擎中，用于测试 **Web Share API** 功能的单元测试文件。它主要验证 `blink::NavigatorShare` 类的行为，确保该类能够正确地处理来自 JavaScript 的 `navigator.share()` 调用，并与底层的浏览器服务进行交互。

以下是该文件的功能详细说明：

**主要功能:**

1. **测试 `navigator.share()` 的核心逻辑:** 该文件通过模拟 JavaScript 环境和用户操作，调用 `NavigatorShare::share()` 方法，并验证其是否按照预期工作。
2. **验证不同类型的共享数据:**  测试用例涵盖了共享文本、URL 和文件的场景，确保 `NavigatorShare` 能够正确地将这些数据传递给浏览器。
3. **模拟共享操作的成功和失败:**  通过使用 `MockShareService` 模拟浏览器端的共享服务，可以测试共享操作成功完成以及被用户取消等不同结果。
4. **检查 UseCounter 的使用:** 验证 Web Share API 的各项特性是否被正确地记录到 Chromium 的 UseCounter 机制中，用于统计功能使用情况。

**与 JavaScript, HTML, CSS 的关系:**

该测试文件直接测试的是 JavaScript API `navigator.share()` 的 Blink 引擎实现，因此与 JavaScript 有着直接的关系。

* **JavaScript 调用:**  测试中的 `Share()` 方法模拟了 JavaScript 调用 `navigator.share()` 的过程，将 `ShareData` 对象传递给 C++ 代码。
    ```c++
    auto promise = NavigatorShare::share(GetScriptState(), *navigator,
                                         &share_data, exception_state);
    ```
    这对应于 JavaScript 中类似这样的代码：
    ```javascript
    navigator.share({
      title: '分享标题',
      text: '分享内容',
      url: 'https://example.com',
      files: [...]
    });
    ```
* **`ShareData` 对象:**  C++ 中的 `ShareData` 类对应于 JavaScript 中传递给 `navigator.share()` 方法的参数对象。测试用例会创建和填充 `ShareData` 对象，模拟 JavaScript 中构建的共享数据。

该文件与 HTML 和 CSS 的关系较为间接：

* **HTML:**  Web Share API 通常通过网页上的交互触发，例如用户点击一个“分享”按钮。虽然这个测试文件没有直接涉及 HTML 结构，但它测试的功能是网页与用户交互的核心部分。测试环境的建立也涉及到一个 DummyPageHolder，这暗示了背后有一个简单的 HTML 文档上下文。
* **CSS:** CSS 主要负责网页的样式和布局，与 Web Share API 的核心功能没有直接关系。该测试文件没有涉及 CSS。

**逻辑推理 (假设输入与输出):**

以下是一些测试用例的逻辑推理示例：

**示例 1: 分享文本、标题和 URL**

* **假设输入:**
    * JavaScript 代码调用 `navigator.share()`，传递包含标题 "Subject"、文本 "Body" 和 URL "https://example.com/path?query#fragment" 的对象。
    * 模拟用户已激活 (通过 `LocalFrame::NotifyUserActivation`)。
    * 底层的 `MockShareService` 模拟共享成功 (`mojom::ShareError::OK`)。
* **预期输出:**
    * `NavigatorShare::share()` 方法调用底层的 `MockShareService` 的 `Share` 方法，传递相同的标题、文本和 URL。
    * `mock_share_service().title()` 返回 "Subject"。
    * `mock_share_service().text()` 返回 "Body"。
    * `mock_share_service().url()` 返回 `KURL("https://example.com/path?query#fragment")`。
    * `mock_share_service().files().size()` 返回 0 (没有文件被分享)。
    * 相关的 UseCounter 被正确记录 (`kWebShareContainingTitle`, `kWebShareContainingText`, `kWebShareContainingUrl`, `kWebShareSuccessfulWithoutFiles`)。
    * `share()` 方法返回的 Promise 状态为 `fulfilled`。

**示例 2: 分享文件**

* **假设输入:**
    * JavaScript 代码调用 `navigator.share()`，传递包含一个名为 "chart.svg"，类型为 "image/svg+xml"，内容为 "<svg></svg>" 的文件的对象。
    * 模拟用户已激活。
    * 底层的 `MockShareService` 模拟共享成功。
* **预期输出:**
    * `NavigatorShare::share()` 方法调用底层的 `MockShareService` 的 `Share` 方法，传递包含一个文件的列表。
    * `mock_share_service().files().size()` 返回 1。
    * `mock_share_service().files()[0]->name.path()` 返回 "chart.svg"。
    * `mock_share_service().files()[0]->blob->GetType()` 返回 "image/svg+xml"。
    * `mock_share_service().files()[0]->blob->size()` 返回 9 ( "<svg></svg>" 的长度)。
    * 相关的 UseCounter 被正确记录 (`kWebShareContainingFiles`, `kWebShareSuccessfulContainingFiles`)。
    * `share()` 方法返回的 Promise 状态为 `fulfilled`。

**示例 3: 用户取消共享**

* **假设输入:**
    * JavaScript 代码调用 `navigator.share()`，传递包含标题 "Subject" 的对象。
    * 模拟用户已激活。
    * 底层的 `MockShareService` 模拟共享被取消 (`mojom::blink::ShareError::CANCELED`)。
* **预期输出:**
    * `NavigatorShare::share()` 方法调用底层的 `MockShareService` 的 `Share` 方法。
    * `mock_share_service().error()` 返回 `mojom::blink::ShareError::CANCELED`。
    * 相关的 UseCounter 被正确记录 (`kWebShareContainingTitle`, `kWebShareUnsuccessfulWithoutFiles`)。
    * `share()` 方法返回的 Promise 状态为 `rejected`。

**用户或编程常见的使用错误:**

1. **未处理 Promise 的 rejection:**  `navigator.share()` 返回一个 Promise，如果共享失败（例如被用户取消），Promise 会被 rejected。开发者需要使用 `.then()` 和 `.catch()` 或 `async/await` 来处理这些情况，否则可能导致未捕获的错误。测试用例 `CancelShare` 和 `CancelShareWithFile` 模拟了这种情况。
    ```javascript
    navigator.share({ title: '...' })
      .then(() => console.log('共享成功'))
      .catch((error) => console.error('共享失败', error));
    ```
2. **在没有用户激活的情况下调用 `navigator.share()`:**  为了安全考虑，`navigator.share()` 只能在用户激活的情况下调用，例如在按钮点击事件处理程序中。如果在没有用户激活的情况下调用，Promise 会被 rejected。测试用例中的 `LocalFrame::NotifyUserActivation` 模拟了用户激活。
    ```javascript
    // 错误示例：在页面加载时立即调用
    navigator.share({ title: '...' }); // 这可能会失败

    // 正确示例：在按钮点击事件中调用
    document.getElementById('shareButton').addEventListener('click', () => {
      navigator.share({ title: '...' });
    });
    ```
3. **传递无效的 `ShareData`:** 例如，传递无法访问的文件、不支持的文件类型，或者超出浏览器限制的文件大小。虽然这个测试文件没有直接测试所有这些错误情况，但底层的 `ShareService` 可能会处理这些错误并返回相应的 `ShareError`。
4. **忘记检查 `navigator.canShare()`:** 在尝试调用 `navigator.share()` 之前，应该先使用 `navigator.canShare()` 检查当前环境是否支持共享以及是否可以共享特定的数据。
    ```javascript
    if (navigator.canShare({ files: [...] })) {
      navigator.share({ files: [...] });
    } else {
      console.log('不支持文件共享');
    }
    ```

**用户操作到达这里的步骤 (调试线索):**

1. **用户在网页上执行了触发共享的操作:**  这通常是点击一个带有“分享”功能的按钮或链接。
2. **网页的 JavaScript 代码调用了 `navigator.share(data)`:**  这个调用发生在用户操作的事件处理程序中，`data` 参数包含了要分享的信息（标题、文本、URL、文件）。
3. **浏览器接收到 JavaScript 的 `navigator.share()` 调用:**  浏览器的主进程将这个调用传递给渲染进程（Blink）。
4. **Blink 引擎处理 `navigator.share()` 调用:**  Blink 引擎中的 JavaScript 代码会调用对应的 C++ 实现，即 `blink::NavigatorShare::share()` 方法。
5. **`NavigatorShare::share()` 方法与浏览器服务交互:**  这个方法会通过 Mojo 接口与浏览器的共享服务 (`mojom::blink::ShareService`) 通信，请求执行共享操作。
6. **浏览器的共享服务接收到请求并执行共享:**  浏览器会弹出系统原生的分享对话框，让用户选择分享的目标应用。
7. **用户完成或取消分享操作:**
    * 如果用户选择了目标应用并成功分享，浏览器的共享服务会通知 Blink 共享成功。
    * 如果用户取消了分享，浏览器的共享服务会通知 Blink 共享被取消。
8. **Blink 引擎更新 Promise 的状态:**  `NavigatorShare::share()` 返回的 Promise 会根据共享的结果被 resolve (成功) 或 reject (失败)。

当开发者需要调试 Web Share API 的问题时，他们可能会：

* **在 JavaScript 代码中设置断点:**  查看传递给 `navigator.share()` 的数据是否正确。
* **在 Blink 引擎的 `NavigatorShare::share()` 方法中设置断点:**  跟踪 C++ 代码的执行流程，查看数据如何传递给浏览器服务。
* **查看浏览器的 Mojo 通信日志:**  了解 Blink 引擎与浏览器共享服务之间的交互。
* **使用 Chromium 的 tracing 工具:**  记录更详细的系统调用和事件，帮助定位问题。

总而言之，`navigator_share_test.cc` 是一个关键的测试文件，用于确保 Chromium 中 Web Share API 的核心功能能够正确地工作，并与 JavaScript API 的行为保持一致。 它通过模拟各种场景和结果，帮助开发者验证和维护 Web Share API 的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/modules/webshare/navigator_share_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webshare/navigator_share.h"

#include <memory>
#include <utility>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file_property_bag.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_blob_usvstring.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_share_data.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using mojom::blink::SharedFile;
using mojom::blink::SharedFilePtr;
using mojom::blink::ShareService;

// A mock ShareService used to intercept calls to the mojo methods.
class MockShareService : public ShareService {
 public:
  MockShareService() : error_(mojom::ShareError::OK) {}
  ~MockShareService() override = default;

  void Bind(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(
        mojo::PendingReceiver<mojom::blink::ShareService>(std::move(handle)));
  }

  void set_error(mojom::ShareError value) { error_ = value; }

  const WTF::String& title() const { return title_; }
  const WTF::String& text() const { return text_; }
  const KURL& url() const { return url_; }
  const WTF::Vector<SharedFilePtr>& files() const { return files_; }
  mojom::ShareError error() const { return error_; }

 private:
  void Share(const WTF::String& title,
             const WTF::String& text,
             const KURL& url,
             WTF::Vector<SharedFilePtr> files,
             ShareCallback callback) override {
    title_ = title;
    text_ = text;
    url_ = url;

    files_.clear();
    files_.ReserveInitialCapacity(files.size());
    for (const auto& entry : files) {
      files_.push_back(entry->Clone());
    }

    std::move(callback).Run(error_);
  }

  mojo::Receiver<ShareService> receiver_{this};
  WTF::String title_;
  WTF::String text_;
  KURL url_;
  WTF::Vector<SharedFilePtr> files_;
  mojom::ShareError error_;
};

class NavigatorShareTest : public testing::Test {
 public:
  NavigatorShareTest()
      : holder_(std::make_unique<DummyPageHolder>()),
        handle_scope_(GetScriptState()->GetIsolate()),
        context_(GetScriptState()->GetContext()),
        context_scope_(context_) {}

  Document& GetDocument() { return holder_->GetDocument(); }

  LocalFrame& GetFrame() { return holder_->GetFrame(); }

  ScriptState* GetScriptState() const {
    return ToScriptStateForMainWorld(&holder_->GetFrame());
  }

  void Share(const ShareData& share_data) {
    LocalFrame::NotifyUserActivation(
        &GetFrame(), mojom::UserActivationNotificationType::kTest);
    Navigator* navigator = GetFrame().DomWindow()->navigator();
    NonThrowableExceptionState exception_state;
    auto promise = NavigatorShare::share(GetScriptState(), *navigator,
                                         &share_data, exception_state);
    test::RunPendingTasks();
    EXPECT_EQ(mock_share_service_.error() == mojom::ShareError::OK
                  ? v8::Promise::kFulfilled
                  : v8::Promise::kRejected,
              promise.V8Promise()->State());
  }

  MockShareService& mock_share_service() { return mock_share_service_; }

 protected:
  void SetUp() override {
    GetFrame().Loader().CommitNavigation(
        WebNavigationParams::CreateWithEmptyHTMLForTesting(
            KURL("https://example.com")),
        nullptr /* extra_data */);
    test::RunPendingTasks();

    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        ShareService::Name_,
        WTF::BindRepeating(&MockShareService::Bind,
                           WTF::Unretained(&mock_share_service_)));
  }

  void TearDown() override {
    // Remove the testing binder to avoid crashes between tests caused by
    // MockShareService rebinding an already-bound Binding.
    // See https://crbug.com/1010116 for more information.
    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        ShareService::Name_, {});

    MemoryCache::Get()->EvictResources();
  }

 public:
  test::TaskEnvironment task_environment;
  MockShareService mock_share_service_;

  std::unique_ptr<DummyPageHolder> holder_;
  v8::HandleScope handle_scope_;
  v8::Local<v8::Context> context_;
  v8::Context::Scope context_scope_;
};

TEST_F(NavigatorShareTest, ShareText) {
  const String title = "Subject";
  const String message = "Body";
  const String url = "https://example.com/path?query#fragment";

  ShareData* share_data = MakeGarbageCollected<ShareData>();
  share_data->setTitle(title);
  share_data->setText(message);
  share_data->setUrl(url);
  Share(*share_data);

  EXPECT_EQ(mock_share_service().title(), title);
  EXPECT_EQ(mock_share_service().text(), message);
  EXPECT_EQ(mock_share_service().url(), KURL(url));
  EXPECT_EQ(mock_share_service().files().size(), 0U);
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kWebShareContainingTitle));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kWebShareContainingText));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kWebShareContainingUrl));
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kWebShareSuccessfulWithoutFiles));
}

File* CreateSampleFile(ExecutionContext* context,
                       const String& file_name,
                       const String& content_type,
                       const String& file_contents) {
  HeapVector<Member<V8BlobPart>> blob_parts;
  blob_parts.push_back(MakeGarbageCollected<V8BlobPart>(file_contents));

  FilePropertyBag* file_property_bag = MakeGarbageCollected<FilePropertyBag>();
  file_property_bag->setType(content_type);
  return File::Create(context, blob_parts, file_name, file_property_bag);
}

TEST_F(NavigatorShareTest, ShareFile) {
  const String file_name = "chart.svg";
  const String content_type = "image/svg+xml";
  const String file_contents = "<svg></svg>";

  HeapVector<Member<File>> files;
  files.push_back(CreateSampleFile(ExecutionContext::From(GetScriptState()),
                                   file_name, content_type, file_contents));

  ShareData* share_data = MakeGarbageCollected<ShareData>();
  share_data->setFiles(files);
  Share(*share_data);

  EXPECT_EQ(mock_share_service().files().size(), 1U);
  EXPECT_EQ(mock_share_service().files()[0]->name.path(),
            StringToFilePath(file_name));
  EXPECT_EQ(mock_share_service().files()[0]->blob->GetType(), content_type);
  EXPECT_EQ(mock_share_service().files()[0]->blob->size(),
            file_contents.length());
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kWebShareContainingFiles));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kWebShareSuccessfulContainingFiles));
}

TEST_F(NavigatorShareTest, CancelShare) {
  const String title = "Subject";
  ShareData* share_data = MakeGarbageCollected<ShareData>();
  share_data->setTitle(title);

  mock_share_service().set_error(mojom::blink::ShareError::CANCELED);
  Share(*share_data);
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kWebShareContainingTitle));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kWebShareUnsuccessfulWithoutFiles));
}

TEST_F(NavigatorShareTest, CancelShareWithFile) {
  const String file_name = "counts.csv";
  const String content_type = "text/csv";
  const String file_contents = "1,2,3";

  const String url = "https://example.site";

  HeapVector<Member<File>> files;
  files.push_back(CreateSampleFile(ExecutionContext::From(GetScriptState()),
                                   file_name, content_type, file_contents));

  ShareData* share_data = MakeGarbageCollected<ShareData>();
  share_data->setFiles(files);
  share_data->setUrl(url);

  mock_share_service().set_error(mojom::blink::ShareError::CANCELED);
  Share(*share_data);
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kWebShareContainingFiles));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kWebShareContainingUrl));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kWebShareUnsuccessfulContainingFiles));
}

}  // namespace blink
```