Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of a unit test for the Shared Storage API in the Chromium browser. I need to identify the main features being tested and how they relate to web technologies like JavaScript, HTML, and CSS. I also need to find examples of logic, potential user errors, and how a user might trigger this code. Finally, I need to remember this is part 3 of 5.

**Plan:**

1. **Identify the main testing targets:** Look for `TEST_F` declarations to understand which functionalities are being tested.
2. **Analyze the JavaScript code within the tests:**  This will reveal the API features being exercised.
3. **Connect to web technologies:** Explain how the tested JavaScript API relates to HTML, CSS, and general web development.
4. **Find examples of logic:**  Look for conditional statements and data manipulation in the JavaScript and the test setup.
5. **Identify potential user errors:**  Consider how a web developer might misuse the Shared Storage API.
6. **Explain user operations leading to this code:**  Describe the sequence of actions a user takes in a browser that would trigger the execution of this Shared Storage code.
7. **Summarize the functionality:**  Provide a concise overview of what the code is testing.
这是对`blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc`文件的第三部分代码的分析，主要涵盖了以下功能点的单元测试：

**功能归纳:**

* **`interestGroups()` API 测试:**
    * 测试 `interestGroups()` 方法能否成功获取 Interest Groups 信息。
    * 验证返回的 Interest Groups 数据的结构和内容是否符合预期，包括各种字段的值和类型。
    * 模拟并验证返回的持续时间值的精度问题，允许一定的误差范围。
    * 使用自定义的排序函数 `sortObjectByKeyRecursive` 对返回的 Interest Groups 进行排序，并与预期的排序结果进行比较。
* **`sharedStorage.set()` API 测试:**
    * 测试 `sharedStorage.set()` 方法的基本功能，即设置一个键值对。
    * 测试 `ignoreIfPresent` 参数的不同取值（`true`，`false`，以及其他会被转换为布尔值的类型）对 `set()` 方法行为的影响。
    * 测试 `set()` 方法会将键和值转换为字符串。
    * 测试当键或值的 `toString()` 方法抛出错误时，`set()` 方法的处理情况。
* **`sharedStorage.append()` API 测试:**
    * 测试 `sharedStorage.append()` 方法的基本功能，即向指定键追加值。
    * 测试缺少参数、键为空字符串或过长、值过长等非法参数情况下 `append()` 方法的错误处理。
    * 模拟后端服务返回错误时 `append()` 方法的处理情况。
* **`sharedStorage.delete()` API 测试:**
    * 测试 `sharedStorage.delete()` 方法的基本功能，即删除指定键的值。
    * 测试缺少参数、键为空字符串或过长等非法参数情况下 `delete()` 方法的错误处理。
    * 模拟后端服务返回错误时 `delete()` 方法的处理情况。
* **`sharedStorage.clear()` API 测试:**
    * 测试 `sharedStorage.clear()` 方法的基本功能，即清空所有存储。
    * 模拟后端服务返回错误时 `clear()` 方法的处理情况。
* **`sharedStorage.get()` API 测试:**
    * 测试 `sharedStorage.get()` 方法的基本功能，即获取指定键的值。
    * 测试缺少参数、键为空字符串或过长等非法参数情况下 `get()` 方法的错误处理。
    * 模拟后端服务返回错误以及键不存在（`NotFound`）的情况。
* **`sharedStorage.length()` API 测试:**
    * 测试 `sharedStorage.length()` 方法的基本功能，即获取存储中键值对的数量。
    * 模拟后端服务返回错误的情况。
* **`sharedStorage.entries()` API 测试:**
    * 测试 `sharedStorage.entries()` 方法的异步迭代功能，用于遍历存储中的所有键值对。
    * 测试当第一次迭代返回空批次时的处理情况。
    * 测试当第一次迭代发生错误时的处理情况。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些测试直接关联到浏览器提供的 JavaScript API，用于操作 Shared Storage。Shared Storage 是一种在浏览器中存储数据的机制，与浏览器的其他存储机制（如 Cookie、LocalStorage）不同，它具有特定的使用场景和限制，例如在 Privacy Sandbox 的上下文中。

* **JavaScript:**  测试代码中包含了大量的 JavaScript 代码片段，这些代码片段模拟了开发者在 Worklet 中使用 Shared Storage API 的方式。例如，`await sharedStorage.set("key0", "value0");` 这段代码直接使用了 JavaScript 的 `sharedStorage` 对象及其 `set` 方法。
* **HTML:** 虽然这个测试文件本身不涉及 HTML，但 Shared Storage API 是通过 JavaScript 在网页上下文中使用的。开发者会在 HTML 中嵌入的 `<script>` 标签内的 JavaScript 代码中使用这些 API。例如，一个广告服务提供商可能会在他们的广告脚本中使用 Shared Storage 来存储与用户兴趣相关的信息。
* **CSS:**  CSS 与 Shared Storage 的功能没有直接关系。Shared Storage 主要用于存储数据，而 CSS 用于控制网页的样式和布局。

**逻辑推理、假设输入与输出:**

**示例 1: `interestGroups()` 测试**

* **假设输入:**  模拟返回一个包含单个 Interest Group 信息的 `groups` 对象。该对象包含预设的 `lifetimeRemainingMs`, `prevWinsMs`, `timeSinceGroupJoinedMs` 等字段，以及各种 Interest Group 的配置信息。
* **逻辑推理:** 测试代码会调用 Worklet 中的 `interestGroups()` 方法，获取返回的 Interest Group 信息。然后，它会逐个检查返回对象的字段值是否在预期的范围内（对于时间相关的字段允许一定误差）。最后，它会对返回的复杂对象进行排序，并与预期的排序后的 JSON 字符串进行严格比较。
* **预期输出:** 如果返回的 Interest Group 信息与预期一致（包括在误差范围内的持续时间值），且排序后的 JSON 字符串与预期完全相同，则测试通过。否则，测试会抛出包含具体错误信息的异常。

**示例 2: `sharedStorage.set()` 测试**

* **假设输入:** Worklet 中执行 `await sharedStorage.set("key0", "value0");`
* **逻辑推理:** 测试代码会捕获 Worklet 中对 `sharedStorage.set()` 的调用。它会检查传递给 `set()` 方法的键和值是否与预期一致。
* **预期输出:**  测试会检查 `test_client_->observed_update_params_` 中是否包含一个 `set` 操作，并且该操作的键为 `"key0"`，值为 `"value0"`。

**用户或编程常见的使用错误举例:**

* **`sharedStorage.append()` 缺少参数:**  开发者可能错误地调用 `await sharedStorage.append("key");` 而没有提供要追加的值。测试会捕获到这个错误，并验证 Worklet 是否抛出了参数数量不匹配的异常。
* **`sharedStorage.get()` 使用空字符串作为键:** 开发者可能错误地使用空字符串作为 `get()` 方法的键，例如 `await sharedStorage.get("");`。测试会验证 Worklet 是否捕获到这个错误，并抛出键长度无效的异常。
* **`sharedStorage.set()` 传递复杂对象作为键或值，但未考虑到字符串转换:**  虽然 `set()` 会将键和值转换为字符串，但开发者可能没有意识到这一点，并错误地假设传递对象会按对象进行存储。例如，`await sharedStorage.set({dictKey1: 'dictValue1'}, {dictKey2: 'dictValue2'});`，最终存储的键和值都会是 `"[object Object]"`。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个包含 Shared Storage 功能的网页:**  用户在浏览器中打开了一个网页，该网页的 JavaScript 代码使用了 Shared Storage API。
2. **网页 JavaScript 代码执行:** 网页加载后，其中的 JavaScript 代码开始执行。
3. **调用 Shared Storage API:**  JavaScript 代码调用了 `navigator.sharedStorage` 对象上的方法，例如 `sharedStorage.set()`, `sharedStorage.get()`, `sharedStorage.interestGroups()` 等。
4. **浏览器处理 Shared Storage 请求:** 浏览器接收到 JavaScript 的 Shared Storage API 调用请求。
5. **Worklet 执行:**  对于一些需要隔离执行的操作（例如 `interestGroups()`），浏览器可能会创建一个 Shared Storage Worklet 来执行相应的代码。
6. **单元测试模拟 Worklet 执行:**  在单元测试中，`SharedStorageWorkletTest` 类模拟了 Worklet 的执行环境。测试代码会加载包含 Shared Storage API 调用的 JavaScript 代码，并在模拟的环境中运行。
7. **测试验证 API 行为:**  测试代码会断言 API 的行为是否符合预期，例如检查是否正确地调用了底层的浏览器接口，以及返回的结果是否正确。

**总结本部分功能:**

这部分代码主要集中测试了 Shared Storage Worklet 中可以使用的 JavaScript API 的各种功能，包括获取 Interest Groups 信息 (`interestGroups()`) 以及对 Shared Storage 数据进行增删改查操作 (`set()`, `append()`, `delete()`, `clear()`, `get()`, `length()`, `entries()`)。测试覆盖了正常情况和各种异常情况，例如参数错误、后端服务错误等，确保这些 API 在 Worklet 环境下的行为符合预期。

### 提示词
```
这是目录为blink/renderer/modules/shared_storage/shared_storage_worklet_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
push_back(std::move(storage_interest_group));

  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      function sortObjectByKeyRecursive(obj) {
        if (Array.isArray(obj)) {
          return obj.map(sortObjectByKeyRecursive);
        }
        else if (typeof obj === 'object' && obj !== null) {
          const sortedKeys = Object.keys(obj).sort();
          const sortedObj = {};
          for (const key of sortedKeys) {
            sortedObj[key] = sortObjectByKeyRecursive(obj[key]);
          }
          return sortedObj;
        }
        else {
          return obj;
        }
      }

      // Compare two durations with a tolerance for slight differences.
      // Due to the test execution happening in real-time, the exact durations
      // may not match perfectly. This function accounts for minor variations to
      // ensure robust test assertions.
      function areDurationsClose(d1, d2) {
        const diff = d1 - d2;
        if (diff <= 2000 && diff >= -2000) {
          return true;
        }
        return false;
      }

      class TestClass {
        async run() {
          const groups = await interestGroups();

          if (groups.length !== 1) {
            throw Error("Unexpected groups.length: " + groups.length);
          }

          const expectedLifetimeRemainingMs = 3000000;
          const expectedPreviousWinLifetimeMs = 500000;
          const expectedTimeSinceGroupJoinedMs = 2000000;
          const expectedTimeSinceLastUpdateMs = 1500000;
          const expectedTimeUntilNextUpdateMs = 2000000;

          if (areDurationsClose(groups[0]["lifetimeRemainingMs"],
              expectedLifetimeRemainingMs)) {
            groups[0]["lifetimeRemainingMs"] = "<verified duration>";
          } else {
            throw Error("Unexpected groups[0][\"lifetimeRemainingMs\"]: " +
              groups[0]["lifetimeRemainingMs"]);
          }

          if (groups[0]["prevWinsMs"].length !== 1) {
            throw Error("Unexpected groups[0][\"prevWinsMs\"].length: " +
              groups[0]["prevWinsMs"].length);
          }

          if (groups[0]["prevWinsMs"][0].length !== 2) {
            throw Error("Unexpected groups[0][\"prevWinsMs\"][0].length: " +
              groups[0]["prevWinsMs"][0].length);
          }

          if (areDurationsClose(groups[0]["prevWinsMs"][0][0],
              expectedPreviousWinLifetimeMs)) {
            groups[0]["prevWinsMs"][0][0] = "<verified duration>";
          } else {
            throw Error(
              "Unexpected groups[0][\"prevWinsMs\"][0][0]: " +
              groups[0]["prevWinsMs"][0][0]);
          }

          if (areDurationsClose(groups[0]["timeSinceGroupJoinedMs"],
              expectedTimeSinceGroupJoinedMs)) {
            groups[0]["timeSinceGroupJoinedMs"] = "<verified duration>";
          } else {
            throw Error("Unexpected groups[0][\"timeSinceGroupJoinedMs\"]: " +
              groups[0]["timeSinceGroupJoinedMs"]);
          }

          if (areDurationsClose(groups[0]["timeSinceLastUpdateMs"],
              expectedTimeSinceLastUpdateMs)) {
            groups[0]["timeSinceLastUpdateMs"] = "<verified duration>";
          } else {
            throw Error("Unexpected groups[0][\"timeSinceLastUpdateMs\"]: " +
              groups[0]["timeSinceLastUpdateMs"]);
          }

          if (areDurationsClose(groups[0]["timeUntilNextUpdateMs"],
              expectedTimeUntilNextUpdateMs)) {
            groups[0]["timeUntilNextUpdateMs"] = "<verified duration>";
          } else {
            throw Error("Unexpected groups[0][\"timeUntilNextUpdateMs\"]: " +
              groups[0]["timeUntilNextUpdateMs"]);
          }

          const actualSortedGroups = sortObjectByKeyRecursive(groups);

          const expectedSortedGroups = [
            {
              "adComponents": [
                {
                  "metadata": "meta3",
                  "renderURL": "https://example.com/locomotive",
                  "renderUrl": "https://example.com/locomotive"
                },
                {
                  "metadata": "meta4",
                  "renderURL": "https://example.com/turbojet",
                  "renderUrl": "https://example.com/turbojet"
                }
              ],
              "adSizes": {
                "small": {
                  "height": "5sh",
                  "width": "100px"
                }
              },
              "additionalBidKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "ads": [
                {
                  "adRenderId": "ad_render_id",
                  "allowedReportingOrigins": [
                    "https://reporting.example.org"
                  ],
                  "buyerAndSellerReportingId": "bsid",
                  "buyerReportingId": "bid",
                  "metadata": "metadata",
                  "renderURL": "https://example.com/train",
                  "renderUrl": "https://example.com/train",
                  "selectableBuyerAndSellerReportingIds": [
                    "selectable_id1",
                    "selectable_id2"
                  ],
                  "sizeGroup": "sizegroup"
                },
                {
                  "metadata": "meta2",
                  "renderURL": "https://example.com/plane",
                  "renderUrl": "https://example.com/plane"
                }
              ],
              "auctionServerRequestFlags": [
                "omit-ads"
              ],
              "bidCount": 2,
              "biddingLogicURL": "https://example.org/bid.js",
              "biddingLogicUrl": "https://example.org/bid.js",
              "biddingWasmHelperURL": "https://example.org/bid.wasm",
              "biddingWasmHelperUrl": "https://example.org/bid.wasm",
              "enableBiddingSignalsPrioritization": true,
              "estimatedSize": 1000,
              "executionMode": "group-by-origin",
              "joinCount": 1,
              "joiningOrigin": "https://joining-origin.com",
              "lifetimeRemainingMs": "<verified duration>",
              "maxTrustedBiddingSignalsURLLength": 100,
              "name": "ig_one",
              "owner": "https://example.org",
              "prevWinsMs": [
                [
                  "<verified duration>",
                  {
                    "adRenderId": "render-id",
                    "metadata": {
                      "abc": 1,
                      "def": 2
                    },
                    "renderURL": "https://render-url.com"
                  }
                ]
              ],
              "priority": 5.5,
              "prioritySignalsOverrides": {
                "a": 0.5,
                "b": 2
              },
              "priorityVector": {
                "i": 1,
                "j": 2,
                "k": 4
              },
              "privateAggregationConfig": {
                "aggregationCoordinatorOrigin": "https://aggegator.example.org"
              },
              "sellerCapabilities": {
                "https://example.org": [
                  "interest-group-counts"
                ]
              },
              "sizeGroups": {
                "g1": [
                  "small",
                  "medium"
                ],
                "g2": [
                  "large"
                ]
              },
              "timeSinceGroupJoinedMs": "<verified duration>",
              "timeSinceLastUpdateMs": "<verified duration>",
              "timeUntilNextUpdateMs": "<verified duration>",
              "trustedBiddingSignalsCoordinator": "https://example.test",
              "trustedBiddingSignalsKeys": [
                "l",
                "m"
              ],
              "trustedBiddingSignalsSlotSizeMode": "all-slots-requested-sizes",
              "trustedBiddingSignalsURL": "https://example.org/trust.json",
              "trustedBiddingSignalsUrl": "https://example.org/trust.json",
              "updateURL": "https://example.org/ig_update.json",
              "updateUrl": "https://example.org/ig_update.json",
              "userBiddingSignals": "hello"
            }
          ];

          if (JSON.stringify(actualSortedGroups) !== JSON.stringify(
              expectedSortedGroups)) {
            throw Error("Actual groups: " + JSON.stringify(actualSortedGroups) +
              "\nExpected groups: " + JSON.stringify(expectedSortedGroups));
          }
        }
      };

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->interest_groups_result_ =
      blink::mojom::GetInterestGroupsResult::NewGroups(std::move(groups));

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_EQ(run_result.error_message, "");

  EXPECT_EQ(test_client_->observed_get_interest_groups_count_, 1u);
}

TEST_F(SharedStorageWorkletTest, Set_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set("key0", "value0");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_update_params_.size(), 1u);
  network::mojom::SharedStorageSetMethodPtr& observed_params =
      test_client_->observed_update_params_[0]->get_set_method();
  EXPECT_EQ(observed_params->key, u"key0");
  EXPECT_EQ(observed_params->value, u"value0");
}

TEST_F(SharedStorageWorkletTest, Set_IgnoreIfPresent_True) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set("key", "value", {ignoreIfPresent: true});

          // A non-empty string will evaluate to true.
          await sharedStorage.set("key", "value", {ignoreIfPresent: "false"});

          // A dictionary object will evaluate to true.
          await sharedStorage.set("key", "value", {ignoreIfPresent: {}});
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_update_params_.size(), 3u);
  EXPECT_TRUE(test_client_->observed_update_params_[0]
                  ->get_set_method()
                  ->ignore_if_present);
  EXPECT_TRUE(test_client_->observed_update_params_[1]
                  ->get_set_method()
                  ->ignore_if_present);
  EXPECT_TRUE(test_client_->observed_update_params_[2]
                  ->get_set_method()
                  ->ignore_if_present);
}

TEST_F(SharedStorageWorkletTest, Set_IgnoreIfPresent_False) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set("key", "value");
          await sharedStorage.set("key", "value", {});
          await sharedStorage.set("key", "value", {ignoreIfPresent: false});
          await sharedStorage.set("key", "value", {ignoreIfPresent: ""});
          await sharedStorage.set("key", "value", {ignoreIfPresent: null});
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_update_params_.size(), 5u);
  EXPECT_FALSE(test_client_->observed_update_params_[0]
                   ->get_set_method()
                   ->ignore_if_present);
  EXPECT_FALSE(test_client_->observed_update_params_[1]
                   ->get_set_method()
                   ->ignore_if_present);
  EXPECT_FALSE(test_client_->observed_update_params_[2]
                   ->get_set_method()
                   ->ignore_if_present);
  EXPECT_FALSE(test_client_->observed_update_params_[3]
                   ->get_set_method()
                   ->ignore_if_present);
  EXPECT_FALSE(test_client_->observed_update_params_[4]
                   ->get_set_method()
                   ->ignore_if_present);
}

TEST_F(SharedStorageWorkletTest, Set_KeyAndValueConvertedToString) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.set(123, 456);
          await sharedStorage.set(null, null);
          await sharedStorage.set(undefined, undefined);
          await sharedStorage.set({dictKey1: 'dictValue1'}, {dictKey2: 'dictValue2'});
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_update_params_.size(), 4u);

  network::mojom::SharedStorageSetMethodPtr& observed_params_0 =
      test_client_->observed_update_params_[0]->get_set_method();
  EXPECT_EQ(observed_params_0->key, u"123");
  EXPECT_EQ(observed_params_0->value, u"456");

  network::mojom::SharedStorageSetMethodPtr& observed_params_1 =
      test_client_->observed_update_params_[1]->get_set_method();
  EXPECT_EQ(observed_params_1->key, u"null");
  EXPECT_EQ(observed_params_1->value, u"null");

  network::mojom::SharedStorageSetMethodPtr& observed_params_2 =
      test_client_->observed_update_params_[2]->get_set_method();
  EXPECT_EQ(observed_params_2->key, u"undefined");
  EXPECT_EQ(observed_params_2->value, u"undefined");

  network::mojom::SharedStorageSetMethodPtr& observed_params_3 =
      test_client_->observed_update_params_[3]->get_set_method();
  EXPECT_EQ(observed_params_3->key, u"[object Object]");
  EXPECT_EQ(observed_params_3->value, u"[object Object]");
}

TEST_F(SharedStorageWorkletTest, Set_ParamConvertedToStringError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          class CustomClass {
            toString() { throw Error("error 123"); }
          };

          await sharedStorage.set(new CustomClass(), "value");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Append_MissingKey) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.append();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("2 arguments required, but only 0 present"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Append_InvalidKey_Empty) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.append("", "value");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"key\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Append_InvalidKey_TooLong) {
  AddModuleResult add_module_result = AddModule(
      /*script_content=*/base::ReplaceStringPlaceholders(
          R"(
      class TestClass {
        async run() {
          await sharedStorage.append("a".repeat($1), "value");
        }
      }

      register("test-operation", TestClass);
  )",
          {kMaxChar16StringLengthPlusOneLiteral},
          /*offsets=*/nullptr));

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"key\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Append_MissingValue) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.append("key");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("2 arguments required, but only 1 present"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Append_InvalidValue_TooLong) {
  AddModuleResult add_module_result = AddModule(
      /*script_content=*/base::ReplaceStringPlaceholders(
          R"(
      class TestClass {
        async run() {
          await sharedStorage.append("key", "a".repeat($1));
        }
      }

      register("test-operation", TestClass);
  )",
          {kMaxChar16StringLengthPlusOneLiteral},
          /*offsets=*/nullptr));

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"value\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Append_ClientError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.append("key0", "value0");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->update_result_error_message_ = "error 123";

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 1u);
  network::mojom::SharedStorageAppendMethodPtr& observed_params =
      test_client_->observed_update_params_[0]->get_append_method();
  EXPECT_EQ(observed_params->key, u"key0");
  EXPECT_EQ(observed_params->value, u"value0");
}

TEST_F(SharedStorageWorkletTest, Append_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.append("key0", "value0");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_update_params_.size(), 1u);
  network::mojom::SharedStorageAppendMethodPtr& observed_params =
      test_client_->observed_update_params_[0]->get_append_method();
  EXPECT_EQ(observed_params->key, u"key0");
  EXPECT_EQ(observed_params->value, u"value0");
}

TEST_F(SharedStorageWorkletTest, Delete_MissingKey) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.delete();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("1 argument required, but only 0 present"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Delete_InvalidKey_Empty) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.delete("");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"key\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Delete_InvalidKey_TooLong) {
  AddModuleResult add_module_result = AddModule(
      /*script_content=*/base::ReplaceStringPlaceholders(
          R"(
      class TestClass {
        async run() {
          await sharedStorage.delete("a".repeat($1), "value");
        }
      }

      register("test-operation", TestClass);
  )",
          {kMaxChar16StringLengthPlusOneLiteral},
          /*offsets=*/nullptr));

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"key\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Delete_ClientError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.delete("key0");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->update_result_error_message_ = "error 123";

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 1u);
  network::mojom::SharedStorageDeleteMethodPtr& observed_params =
      test_client_->observed_update_params_[0]->get_delete_method();
  EXPECT_EQ(observed_params->key, u"key0");
}

TEST_F(SharedStorageWorkletTest, Delete_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.delete("key0");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_update_params_.size(), 1u);
  network::mojom::SharedStorageDeleteMethodPtr& observed_params =
      test_client_->observed_update_params_[0]->get_delete_method();
  EXPECT_EQ(observed_params->key, u"key0");
}

TEST_F(SharedStorageWorkletTest, Clear_ClientError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.clear();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->update_result_error_message_ = "error 123";

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));

  EXPECT_EQ(test_client_->observed_update_params_.size(), 1u);
}

TEST_F(SharedStorageWorkletTest, Clear_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.clear();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_update_params_.size(), 1u);
}

TEST_F(SharedStorageWorkletTest, Get_MissingKey) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.get();
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message,
              testing::HasSubstr("1 argument required, but only 0 present"));

  EXPECT_EQ(test_client_->observed_get_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Get_InvalidKey_Empty) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          await sharedStorage.get("");
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"key\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_get_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Get_InvalidKey_TooLong) {
  AddModuleResult add_module_result = AddModule(
      /*script_content=*/base::ReplaceStringPlaceholders(
          R"(
      class TestClass {
        async run() {
          await sharedStorage.get("a".repeat($1), "value");
        }
      }

      register("test-operation", TestClass);
  )",
          {kMaxChar16StringLengthPlusOneLiteral},
          /*offsets=*/nullptr));

  EXPECT_TRUE(add_module_result.success);

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(
      run_result.error_message,
      testing::HasSubstr("Length of the \"key\" parameter is not valid"));

  EXPECT_EQ(test_client_->observed_get_params_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Get_ClientError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          let a = await sharedStorage.get("key0");
          console.log(a);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->get_result_ =
      GetResult{.status = blink::mojom::SharedStorageGetStatus::kError,
                .error_message = "error 123",
                .value = std::u16string()};

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));

  EXPECT_EQ(test_client_->observed_get_params_.size(), 1u);
  EXPECT_EQ(test_client_->observed_get_params_[0], u"key0");

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Get_NotFound) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          let a = await sharedStorage.get("key0");
          console.log(a);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->get_result_ =
      GetResult{.status = blink::mojom::SharedStorageGetStatus::kNotFound,
                .error_message = std::string(),
                .value = std::u16string()};

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_get_params_.size(), 1u);
  EXPECT_EQ(test_client_->observed_get_params_[0], u"key0");

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "undefined");
}

TEST_F(SharedStorageWorkletTest, Get_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          let a = await sharedStorage.get("key0");
          console.log(a);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->get_result_ =
      GetResult{.status = blink::mojom::SharedStorageGetStatus::kSuccess,
                .error_message = std::string(),
                .value = u"value0"};

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_get_params_.size(), 1u);
  EXPECT_EQ(test_client_->observed_get_params_[0], u"key0");

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "value0");
}

TEST_F(SharedStorageWorkletTest, Length_ClientError) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          let a = await sharedStorage.length();
          console.log(a);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->length_result_ =
      LengthResult{.success = false, .error_message = "error 123", .length = 0};

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_FALSE(run_result.success);
  EXPECT_THAT(run_result.error_message, testing::HasSubstr("error 123"));

  EXPECT_EQ(test_client_->observed_length_count_, 1u);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Length_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          let a = await sharedStorage.length();
          console.log(a);
        }
      }

      register("test-operation", TestClass);
  )");

  EXPECT_TRUE(add_module_result.success);

  test_client_->length_result_ = LengthResult{
      .success = true, .error_message = std::string(), .length = 123};

  RunResult run_result = Run("test-operation", CreateSerializedUndefined());

  EXPECT_TRUE(run_result.success);
  EXPECT_TRUE(run_result.error_message.empty());

  EXPECT_EQ(test_client_->observed_length_count_, 1u);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 1u);
  EXPECT_EQ(test_client_->observed_console_log_messages_[0], "123");
}

TEST_F(SharedStorageWorkletTest, Entries_OneEmptyBatch_Success) {
  AddModuleResult add_module_result = AddModule(/*script_content=*/R"(
      class TestClass {
        async run() {
          for await (const [key, value] of sharedStorage.entries()) {
            console.log(key + ';' + value);
          }
        }
      }

      register("test-operation", TestClass);
  )");

  base::test::TestFuture<bool, const std::string&> run_future;
  shared_storage_worklet_service_->RunOperation(
      "test-operation", CreateSerializedUndefined(),
      MaybeInitPAOperationDetails(), run_future.GetCallback());
  shared_storage_worklet_service_.FlushForTesting();

  EXPECT_FALSE(run_future.IsReady());
  EXPECT_EQ(test_client_->pending_entries_listeners_.size(), 1u);

  mojo::Remote<blink::mojom::SharedStorageEntriesListener> listener =
      test_client_->TakeEntriesListenerAtFront();
  listener->DidReadEntries(
      /*success=*/true, /*error_message=*/{}, CreateBatchResult({}),
      /*has_more_entries=*/false, /*total_queued_to_send=*/0);

  RunResult run_result{run_future.Get<0>(), run_future.Get<1>()};
  EXPECT_TRUE(run_result.success);

  EXPECT_EQ(test_client_->observed_console_log_messages_.size(), 0u);
}

TEST_F(SharedStorageWorkletTest, Entries_FirstBatchError_Failure) {
  AddModuleR
```