Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Core Goal:** The filename `storage_controller_test.cc` immediately tells us this is a test file for something called `StorageController`. Test files verify the functionality of a specific component.

2. **Identify Key Components:** Scan the `#include` directives to see what other parts of the Blink engine are involved. This gives us context:
    * `storage_controller.h`:  The header file for the class being tested. This is crucial for understanding the `StorageController`'s responsibilities.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates this uses the Google Test framework for unit testing. We can expect `TEST()` macros.
    * `third_party/blink/public/common/features.h`, `tokens/tokens.h`: Likely deals with feature flags and unique identifiers. Less central to the *core* functionality but potentially relevant to its configuration.
    * `renderer/core/frame/...`:  Points to the browser frame structure, particularly `LocalDOMWindow`. This strongly suggests `StorageController` interacts with the browsing context.
    * `renderer/modules/storage/...`: Shows it's part of the broader storage module. `StorageNamespace`, `FakeAreaSource`, and `MockStorageArea` are key collaborators. The "fake" and "mock" keywords suggest testing strategies (isolating dependencies).
    * `platform/...`: Deals with platform-specific abstractions, like task scheduling and URLs.
    * `mojo/public/cpp/bindings/...`:  Crucially, Mojo is involved. This implies inter-process communication, likely between the renderer and the browser process for storage operations.

3. **Analyze the Tests:** Look for `TEST(...)` macros. Each test focuses on a specific aspect of `StorageController`'s behavior.

    * **`CacheLimit`:** The name suggests it tests how the `StorageController` handles limiting the size of its cache for *local storage*. We see:
        * Setting up mocked URLs and `LocalDOMWindow`s to simulate different browsing contexts.
        * Creating a `StorageController`.
        * Getting `LocalStorageArea` instances for different windows.
        * Setting items and checking `quota_used()` and `TotalCacheSize()`.
        * The core logic seems to involve checking if the cache size is managed correctly when adding items and when the limit is reached (the third window triggers cache clearing).

    * **`CacheLimitSessionStorage`:**  Similar to the previous test, but focuses on *session storage*. Key differences:
        * Introduction of `StorageNamespace`. Session storage is namespaced.
        * Interaction with a `MockDomStorage` via Mojo. This confirms the IPC interaction mentioned earlier.
        * Verifying the number of times session storage is "opened" (via `session_storage_opens` in `MockDomStorage`).

4. **Infer Functionality:** Based on the tests and included files, we can infer the `StorageController`'s responsibilities:
    * **Managing storage areas:**  It holds and provides access to storage areas (both local and session).
    * **Caching:** It maintains a cache of these storage areas, likely to improve performance by avoiding repeated IPC calls.
    * **Enforcing cache limits:**  It ensures the cache doesn't grow indefinitely.
    * **Interacting with the browser process:**  It uses Mojo to communicate with the browser process for actual storage operations (the `DomStorage` interface).
    * **Handling different storage scopes:** It distinguishes between local and session storage, and manages namespaces for session storage.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**  Think about how these web technologies use storage:
    * **JavaScript:** The primary way scripts interact with storage via `localStorage` and `sessionStorage`. The tests directly simulate this by setting and getting items.
    * **HTML:**  Meta tags or HTTP headers might influence storage behavior (like setting expiry), but the direct interaction is less obvious in this *renderer-side* test. The test focuses on the *implementation* within the renderer.
    * **CSS:** CSS has no direct way to interact with storage.

6. **Consider User Actions and Debugging:** How does a user end up triggering this code?
    * Opening web pages: Each new tab or window can create new storage areas.
    * JavaScript using `localStorage` or `sessionStorage`: This is the most direct trigger.
    * Navigating between pages: This might involve creating new session storage namespaces or accessing existing local storage.

7. **Identify Potential Errors:** Think about what could go wrong:
    * Exceeding storage quotas.
    * Conflicting access to storage from different frames or processes.
    * Incorrect cache management leading to data loss or inconsistency.
    * Security issues if storage isn't properly isolated.

8. **Construct Examples and Scenarios:**  Formalize the observations with concrete examples for the prompt's requirements (JavaScript interaction, logical inference, user errors, debugging).

9. **Review and Refine:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check if all parts of the prompt have been addressed. For instance, double-check the assumptions made and see if they are well-supported by the code. Ensure the examples are clear and illustrate the points effectively. (Self-correction: Initially, I might have overemphasized HTML's direct role. Refocusing on JavaScript's interaction with the APIs is more accurate given the code.)
好的，让我们来分析一下 `blink/renderer/modules/storage/storage_controller_test.cc` 这个文件。

**功能概述**

这个文件包含了对 `StorageController` 类的单元测试。`StorageController` 在 Chromium Blink 渲染引擎中负责管理和协调 Web Storage (包括 localStorage 和 sessionStorage) 的访问和操作。它主要负责以下几个方面：

1. **管理 StorageArea 的缓存:**  为了提高性能，`StorageController` 会缓存最近使用的 `StorageArea` 对象。这避免了每次访问存储时都进行 IPC 调用。
2. **与浏览器进程通信:** `StorageController` 通过 Mojo 接口与浏览器进程中的 `DomStorage` 服务通信，实际的存储操作在浏览器进程中进行。
3. **管理 Session Storage 的命名空间:**  为不同的浏览上下文 (例如不同的 Tab 或 Frame) 创建和管理独立的 Session Storage 命名空间。
4. **控制缓存大小:**  通过设定缓存限制，防止 `StorageArea` 对象在内存中无限增长。
5. **处理 Storage 事件:** 虽然这个测试文件没有直接体现，但 `StorageController` 也负责触发和传递 Storage 事件，以便在存储发生变化时通知其他窗口或 Frame。

**与 JavaScript, HTML, CSS 的关系**

这个测试文件主要关注 `StorageController` 的内部逻辑，但它的功能直接支持了 JavaScript 中对 Web Storage 的使用。

* **JavaScript:** JavaScript 代码通过 `window.localStorage` 和 `window.sessionStorage` API 来访问 Web Storage。当 JavaScript 代码执行这些 API 时，Blink 渲染引擎会调用 `StorageController` 的相应方法来获取或操作存储区域。

   **举例说明:**

   ```javascript
   // JavaScript 代码
   localStorage.setItem('myKey', 'myValue');
   let value = sessionStorage.getItem('anotherKey');
   ```

   当执行 `localStorage.setItem('myKey', 'myValue')` 时，Blink 引擎内部会经过以下步骤（简化）：

   1. JavaScript 引擎调用 Blink 提供的 API。
   2. 该 API 调用 `StorageController::GetLocalStorageArea()` 获取对应 StorageKey 的 `StorageArea` 对象（如果缓存中没有，则会通过 Mojo 向浏览器进程请求）。
   3. 获取到 `StorageArea` 后，调用其 `SetItem()` 方法。
   4. `StorageArea::SetItem()` 可能会通过 Mojo 将操作发送到浏览器进程进行实际存储。

   类似地，`sessionStorage.getItem('anotherKey')` 会触发 `StorageController` 获取对应的 Session Storage 命名空间和 `StorageArea`。

* **HTML:** HTML 本身不直接操作 Web Storage，但页面的来源 (Origin) 会影响 Web Storage 的隔离和访问权限。`StorageController` 在确定使用哪个 `StorageArea` 时会考虑页面的 Origin。

* **CSS:** CSS 与 Web Storage 没有直接关系。

**逻辑推理与假设输入输出**

这个测试文件主要测试 `StorageController` 的缓存管理逻辑。 让我们分析其中一个测试 `CacheLimit`:

**测试 `CacheLimit` 的逻辑推理:**

* **假设输入:**
    * `kTestCacheLimit` 被设置为 100。
    * 创建了多个不同 Origin 的 `LocalDOMWindow` 对象 (模拟不同的网页)。
    * 每个窗口都尝试访问并使用 localStorage，存储一些键值对。
    * 其中一个窗口存储的值的大小接近或超过 `kTestCacheLimit`。

* **预期输出:**
    * 当访问一个新的 Origin 的 localStorage 且总缓存大小超过 `kTestCacheLimit` 时，`StorageController` 会清理部分缓存，以保证总缓存大小不超过限制。
    * 之前访问过的 Origin 的 `StorageArea` 对象可能会被从缓存中移除。

**具体到测试代码的分析:**

1. **创建多个不同 Origin 的 LocalDOMWindow:** 测试代码使用 `ScopedMockedURLLoad` 和 `frame_test_helpers::WebViewHelper` 创建了多个不同 URL 的 `LocalDOMWindow` 对象 (`local_dom_window`, `local_dom_window2`, `local_dom_window3`)。这模拟了用户访问不同网页的情况。

2. **获取和使用 LocalStorageArea:**  通过 `controller.GetLocalStorageArea(local_dom_window)` 获取每个窗口的 `LocalStorageArea`。

3. **设置键值对:** 使用 `cached_area1->SetItem(kKey, kValue, source_area)` 设置键值对。

4. **检查缓存大小:** 使用 `EXPECT_EQ(expected_total, controller.TotalCacheSize())` 检查总缓存大小。

5. **触发缓存清理:**  当为 `local_dom_window3` 获取 `LocalStorageArea` 之前，`cached_area2` 存储了一个较大的值 (`long_value`)，这可能会导致总缓存大小接近或超过限制。当为 `local_dom_window3` 获取 `LocalStorageArea` 时，预期 `StorageController` 会清理缓存。

6. **验证缓存清理结果:**  `EXPECT_EQ(cached_area2->quota_used(), controller.TotalCacheSize());` 验证缓存大小是否符合预期，即在添加新的 `StorageArea` 后，缓存大小没有无限增长。

**测试 `CacheLimitSessionStorage` 的逻辑推理类似，但关注的是 Session Storage 和命名空间。**

**用户或编程常见的使用错误**

虽然这个测试文件主要测试内部逻辑，但我们可以推断一些与 Web Storage 相关的常见用户或编程错误：

1. **超过存储配额:**  如果用户试图存储的数据量超过浏览器为特定 Origin 分配的配额，`setItem()` 操作可能会失败并抛出 `QUOTA_EXCEEDED_ERR` 异常。 这不是 `StorageController` 直接控制的，而是浏览器进程中的存储服务负责的，但 `StorageController` 负责传递这些错误信息。

   **举例说明:** 用户脚本尝试存储大量数据到 `localStorage`，导致存储失败。

   ```javascript
   try {
       localStorage.setItem('largeData', veryLargeString);
   } catch (e) {
       if (e.name === 'QuotaExceededError') {
           console.error('存储空间不足!');
       }
   }
   ```

2. **误解 Session Storage 的生命周期:**  开发者可能会误以为 `sessionStorage` 的数据在浏览器关闭后仍然存在。实际上，`sessionStorage` 的数据仅在当前会话（通常是单个 Tab 或窗口）中有效。

   **举例说明:**  用户在一个 Tab 页的 `sessionStorage` 中保存了登录信息，然后在另一个 Tab 页尝试访问，结果发现数据不存在。

3. **并发访问和数据竞争:**  在多个窗口或 Frame 中同时修改同一个 Origin 的 `localStorage` 数据时，可能会出现数据竞争的情况。虽然 Web Storage API 会触发 `storage` 事件来通知其他窗口的更改，但开发者需要注意处理并发修改。

   **举例说明:**  两个 Tab 页同时修改同一个 `localStorage` 的键值，后一个保存的操作可能会覆盖前一个。

4. **错误地使用 `JSON.stringify` 和 `JSON.parse`:**  Web Storage 只能存储字符串。如果要存储对象，需要使用 `JSON.stringify()` 将其转换为字符串，读取时再使用 `JSON.parse()` 转换回对象。忘记进行转换会导致存储或读取错误。

   **举例说明:**

   ```javascript
   // 错误地存储对象
   localStorage.setItem('myObject', { a: 1, b: 2 }); // 存储的是 "[object Object]"

   // 正确地存储对象
   localStorage.setItem('myObject', JSON.stringify({ a: 1, b: 2 }));
   let obj = JSON.parse(localStorage.getItem('myObject'));
   ```

**用户操作如何一步步到达这里 (调试线索)**

要调试与 `StorageController` 相关的代码，可能的用户操作路径如下：

1. **用户打开一个网页:** 当用户在浏览器中输入 URL 或点击链接打开一个新的网页时，Blink 渲染进程会为该页面创建一个 `LocalDOMWindow` 对象。

2. **网页执行 JavaScript 代码:** 网页加载完成后，JavaScript 代码开始执行。

3. **JavaScript 代码访问 `localStorage` 或 `sessionStorage`:**  当 JavaScript 代码调用 `window.localStorage.setItem()`, `window.localStorage.getItem()`, `window.sessionStorage.setItem()`, `window.sessionStorage.getItem()` 等方法时，Blink 引擎会捕获这些调用。

4. **Blink 引擎调用 `StorageController` 的方法:**  Blink 引擎会根据 JavaScript 的操作类型和目标存储类型（localStorage 或 sessionStorage），调用 `StorageController` 的相应方法，例如：
   * `GetLocalStorageArea()`: 获取或创建对应 Origin 的 `LocalStorageArea` 对象。
   * `CreateSessionStorageNamespace()`: 为新的浏览上下文创建 Session Storage 命名空间。
   * `GetSessionStorageArea()`: 获取对应命名空间和 Origin 的 `StorageArea` 对象。

5. **`StorageController` 与浏览器进程交互 (Mojo):** 如果需要的 `StorageArea` 不在缓存中，或者需要进行实际的存储操作，`StorageController` 会通过 Mojo 接口调用浏览器进程中的 `DomStorage` 服务。

6. **浏览器进程执行存储操作:** 浏览器进程的 `DomStorage` 服务负责读写磁盘上的存储数据。

7. **数据返回和缓存:** 浏览器进程将操作结果返回给渲染进程的 `StorageController`。`StorageController` 可能会将 `StorageArea` 对象缓存起来，以便下次快速访问。

**调试线索:**

* **断点:** 在 `StorageController` 的关键方法 (例如 `GetLocalStorageArea`, `GetSessionStorageArea`) 设置断点，可以跟踪 JavaScript 存储操作如何触发到这些代码。
* **Mojo 日志:** 查看 Mojo 通信的日志，可以了解 `StorageController` 与浏览器进程之间传递的消息内容。
* **渲染器 DevTools:**  Chromium 的渲染器 DevTools 提供了 Inspector，可以查看 `localStorage` 和 `sessionStorage` 的内容。这可以帮助验证 JavaScript 操作是否按预期影响了存储数据。
* **浏览器进程调试:** 如果问题涉及到实际的存储读写或配额管理，可能需要在浏览器进程中进行调试。

总而言之，`storage_controller_test.cc` 是一个测试 `StorageController` 核心功能的关键文件，它验证了缓存管理、与浏览器进程的交互以及 Session Storage 命名空间管理等逻辑。理解这个文件有助于理解 Blink 引擎如何实现 Web Storage 功能。

### 提示词
```
这是目录为blink/renderer/modules/storage/storage_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/storage/storage_controller.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/task/thread_pool.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/storage/storage_namespace.h"
#include "third_party/blink/renderer/modules/storage/testing/fake_area_source.h"
#include "third_party/blink/renderer/modules/storage/testing/mock_storage_area.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/storage/blink_storage_key.h"
#include "third_party/blink/renderer/platform/testing/scoped_mocked_url.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"

namespace blink {
namespace {

const size_t kTestCacheLimit = 100;
class MockDomStorage : public mojom::blink::DomStorage {
 public:
  // mojom::blink::DomStorage implementation:
  void OpenLocalStorage(
      const blink::BlinkStorageKey& storage_key,
      const blink::LocalFrameToken& local_frame_token,
      mojo::PendingReceiver<mojom::blink::StorageArea> receiver) override {}
  void BindSessionStorageNamespace(
      const String& namespace_id,
      mojo::PendingReceiver<mojom::blink::SessionStorageNamespace> receiver)
      override {}
  void BindSessionStorageArea(
      const blink::BlinkStorageKey& storage_key,
      const blink::LocalFrameToken& local_frame_token,
      const String& namespace_id,
      mojo::PendingReceiver<mojom::blink::StorageArea> receiver) override {
    session_storage_opens++;
  }

  void GetSessionStorageUsage(int32_t* out) const {
    *out = session_storage_opens;
  }

  int32_t session_storage_opens = 0;
};

}  // namespace

TEST(StorageControllerTest, CacheLimit) {
  const String kKey("key");
  const String kValue("value");
  const std::string kRootString = "http://dom_storage/page";
  const KURL kRootUrl = KURL(kRootString.c_str());
  const std::string kPageString = "http://dom_storage1/";
  const KURL kPageUrl = KURL(kPageString.c_str());
  const std::string kPageString2 = "http://dom_storage2/";
  const KURL kPageUrl2 = KURL(kPageString2.c_str());
  const std::string kPageString3 = "http://dom_storage3/";
  const KURL kPageUrl3 = KURL(kPageString3.c_str());

  test::TaskEnvironment task_environment;
  test::ScopedMockedURLLoad scoped_mocked_url_load_root(
      kRootUrl, test::CoreTestDataPath("foo.html"));
  frame_test_helpers::WebViewHelper web_view_helper_root;
  LocalDOMWindow* local_dom_window_root =
      To<LocalDOMWindow>(web_view_helper_root.InitializeAndLoad(kRootString)
                             ->GetPage()
                             ->MainFrame()
                             ->DomWindow());
  Persistent<FakeAreaSource> source_area =
      MakeGarbageCollected<FakeAreaSource>(kRootUrl, local_dom_window_root);

  StorageController::DomStorageConnection connection;
  PostCrossThreadTask(
      *base::ThreadPool::CreateSequencedTaskRunner({}), FROM_HERE,
      CrossThreadBindOnce(
          [](mojo::PendingReceiver<mojom::blink::DomStorage> receiver) {
            mojo::MakeSelfOwnedReceiver(std::make_unique<MockDomStorage>(),
                                        std::move(receiver));
          },
          connection.dom_storage_remote.BindNewPipeAndPassReceiver()));

  StorageController controller(std::move(connection), kTestCacheLimit);

  test::ScopedMockedURLLoad scoped_mocked_url_load(
      kPageUrl, test::CoreTestDataPath("foo.html"));
  frame_test_helpers::WebViewHelper web_view_helper;
  LocalDOMWindow* local_dom_window =
      To<LocalDOMWindow>(web_view_helper.InitializeAndLoad(kPageString)
                             ->GetPage()
                             ->MainFrame()
                             ->DomWindow());
  auto cached_area1 = controller.GetLocalStorageArea(local_dom_window);
  cached_area1->RegisterSource(source_area);
  cached_area1->SetItem(kKey, kValue, source_area);
  const auto* area1_ptr = cached_area1.get();
  size_t expected_total = (kKey.length() + kValue.length()) * 2;
  EXPECT_EQ(expected_total, cached_area1->quota_used());
  EXPECT_EQ(expected_total, controller.TotalCacheSize());
  cached_area1 = nullptr;

  test::ScopedMockedURLLoad scoped_mocked_url_load2(
      kPageUrl2, test::CoreTestDataPath("foo.html"));
  frame_test_helpers::WebViewHelper web_view_helper2;
  LocalDOMWindow* local_dom_window2 =
      To<LocalDOMWindow>(web_view_helper2.InitializeAndLoad(kPageString2)
                             ->GetPage()
                             ->MainFrame()
                             ->DomWindow());
  auto cached_area2 = controller.GetLocalStorageArea(local_dom_window2);
  cached_area2->RegisterSource(source_area);
  cached_area2->SetItem(kKey, kValue, source_area);
  // Area for local_dom_window should still be alive.
  EXPECT_EQ(2 * cached_area2->quota_used(), controller.TotalCacheSize());
  EXPECT_EQ(area1_ptr, controller.GetLocalStorageArea(local_dom_window));

  test::ScopedMockedURLLoad scoped_mocked_url_load3(
      kPageUrl3, test::CoreTestDataPath("foo.html"));
  frame_test_helpers::WebViewHelper web_view_helper3;
  LocalDOMWindow* local_dom_window3 =
      To<LocalDOMWindow>(web_view_helper3.InitializeAndLoad(kPageString3)
                             ->GetPage()
                             ->MainFrame()
                             ->DomWindow());
  String long_value(Vector<UChar>(kTestCacheLimit, 'a'));
  cached_area2->SetItem(kKey, long_value, source_area);
  // Cache is cleared when a new area is opened.
  auto cached_area3 = controller.GetLocalStorageArea(local_dom_window3);
  EXPECT_EQ(cached_area2->quota_used(), controller.TotalCacheSize());
}

TEST(StorageControllerTest, CacheLimitSessionStorage) {
  const String kNamespace1 = WTF::CreateCanonicalUUIDString();
  const String kNamespace2 = WTF::CreateCanonicalUUIDString();
  const String kKey("key");
  const String kValue("value");
  const std::string kRootString = "http://dom_storage/page";
  const KURL kRootUrl = KURL(kRootString.c_str());
  const std::string kPageString = "http://dom_storage1/";
  const KURL kPageUrl = KURL(kPageString.c_str());
  const std::string kPageString2 = "http://dom_storage2/";
  const KURL kPageUrl2 = KURL(kPageString2.c_str());
  const std::string kPageString3 = "http://dom_storage3/";
  const KURL kPageUrl3 = KURL(kPageString3.c_str());

  test::TaskEnvironment task_environment;
  test::ScopedMockedURLLoad scoped_mocked_url_load_root(
      kRootUrl, test::CoreTestDataPath("foo.html"));
  frame_test_helpers::WebViewHelper web_view_helper_root;
  LocalDOMWindow* local_dom_window_root =
      To<LocalDOMWindow>(web_view_helper_root.InitializeAndLoad(kRootString)
                             ->GetPage()
                             ->MainFrame()
                             ->DomWindow());
  Persistent<FakeAreaSource> source_area =
      MakeGarbageCollected<FakeAreaSource>(kRootUrl, local_dom_window_root);

  auto task_runner = base::ThreadPool::CreateSequencedTaskRunner({});

  auto mock_dom_storage = std::make_unique<MockDomStorage>();
  MockDomStorage* dom_storage_ptr = mock_dom_storage.get();

  StorageController::DomStorageConnection connection;
  PostCrossThreadTask(
      *task_runner, FROM_HERE,
      CrossThreadBindOnce(
          [](std::unique_ptr<MockDomStorage> dom_storage_ptr,
             mojo::PendingReceiver<mojom::blink::DomStorage> receiver) {
            mojo::MakeSelfOwnedReceiver(std::move(dom_storage_ptr),
                                        std::move(receiver));
          },
          std::move(mock_dom_storage),
          connection.dom_storage_remote.BindNewPipeAndPassReceiver()));

  StorageController controller(std::move(connection), kTestCacheLimit);

  StorageNamespace* ns1 = controller.CreateSessionStorageNamespace(
      *local_dom_window_root->GetFrame()->GetPage(), kNamespace1);
  StorageNamespace* ns2 = controller.CreateSessionStorageNamespace(
      *local_dom_window_root->GetFrame()->GetPage(), kNamespace2);

  test::ScopedMockedURLLoad scoped_mocked_url_load(
      kPageUrl, test::CoreTestDataPath("foo.html"));
  frame_test_helpers::WebViewHelper web_view_helper;
  LocalDOMWindow* local_dom_window =
      To<LocalDOMWindow>(web_view_helper.InitializeAndLoad(kPageString)
                             ->GetPage()
                             ->MainFrame()
                             ->DomWindow());
  auto cached_area1 = ns1->GetCachedArea(local_dom_window);
  cached_area1->RegisterSource(source_area);
  cached_area1->SetItem(kKey, kValue, source_area);
  const auto* area1_ptr = cached_area1.get();
  size_t expected_total = (kKey.length() + kValue.length()) * 2;
  EXPECT_EQ(expected_total, cached_area1->quota_used());
  EXPECT_EQ(expected_total, controller.TotalCacheSize());
  cached_area1 = nullptr;

  test::ScopedMockedURLLoad scoped_mocked_url_load2(
      kPageUrl2, test::CoreTestDataPath("foo.html"));
  frame_test_helpers::WebViewHelper web_view_helper2;
  LocalDOMWindow* local_dom_window2 =
      To<LocalDOMWindow>(web_view_helper2.InitializeAndLoad(kPageString2)
                             ->GetPage()
                             ->MainFrame()
                             ->DomWindow());
  auto cached_area2 = ns2->GetCachedArea(local_dom_window2);
  cached_area2->RegisterSource(source_area);
  cached_area2->SetItem(kKey, kValue, source_area);
  // Area for local_dom_window should still be alive.
  EXPECT_EQ(2 * cached_area2->quota_used(), controller.TotalCacheSize());
  EXPECT_EQ(area1_ptr, ns1->GetCachedArea(local_dom_window));

  test::ScopedMockedURLLoad scoped_mocked_url_load3(
      kPageUrl3, test::CoreTestDataPath("foo.html"));
  frame_test_helpers::WebViewHelper web_view_helper3;
  LocalDOMWindow* local_dom_window3 =
      To<LocalDOMWindow>(web_view_helper3.InitializeAndLoad(kPageString3)
                             ->GetPage()
                             ->MainFrame()
                             ->DomWindow());
  String long_value(Vector<UChar>(kTestCacheLimit, 'a'));
  cached_area2->SetItem(kKey, long_value, source_area);
  // Cache is cleared when a new area is opened.
  auto cached_area3 = ns1->GetCachedArea(local_dom_window3);
  EXPECT_EQ(cached_area2->quota_used(), controller.TotalCacheSize());

  int32_t opens = 0;
  {
    base::RunLoop loop;
    task_runner->PostTaskAndReply(
        FROM_HERE,
        base::BindOnce(&MockDomStorage::GetSessionStorageUsage,
                       base::Unretained(dom_storage_ptr), &opens),
        loop.QuitClosure());
    loop.Run();
  }
  EXPECT_EQ(opens, 3);
}

}  // namespace blink
```