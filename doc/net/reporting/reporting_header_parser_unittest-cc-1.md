Response:
My thinking process to analyze the provided code snippet and generate the response goes like this:

1. **Understand the Goal:** The request asks for an analysis of a Chromium network stack unit test file (`reporting_header_parser_unittest.cc`), specifically focusing on its functionality, relationship to JavaScript, logical inferences, common user errors, debugging, and a summary of its function within the provided context. Crucially, it's identified as "part 2" of a larger analysis.

2. **Identify the Core Functionality:** The filename and the code snippets clearly point to testing the parsing of HTTP `Reporting` headers. The tests focus on how different header configurations are interpreted and stored in the `ReportingCache`.

3. **Analyze the Test Structure:**  The tests use the `TEST_P` macro, indicating parameterized tests. This means the same test logic is run with different input values (likely different implementations of the `ReportingCache` or related components). The `ReportingHeaderParserTest` class provides setup and utility methods for constructing test headers and verifying cache state.

4. **Break Down Individual Tests:** I go through each `TEST_P` function, identifying its specific purpose:
    * **`Basic`**: Checks adding a single endpoint group with a single endpoint.
    * **`MultipleEndpoints`**: Checks adding an endpoint group with multiple endpoints.
    * **`MultipleGroups`**: Checks adding multiple distinct endpoint groups.
    * **`EndpointGroupKey`**:  Verifies that the combination of NAK, origin, and group name creates a distinct key for endpoint groups. This is a crucial test for correct data isolation.
    * **`HeaderErroneouslyContainsMultipleGroupsOfSameName`**: Tests how the parser handles duplicate group names in the header (it should merge them).
    * **`HeaderErroneouslyContainsGroupsWithRedundantEndpoints`**: Tests deduplication of identical endpoints within a group.
    * **`HeaderErroneouslyContainsMultipleGroupsOfSameNameAndEndpoints`**: Tests deduplication across groups with the same name.
    * **`HeaderErroneouslyContainsGroupsOfSameNameAndOverlappingEndpoints`**: Tests merging of endpoints from groups with the same name but different sets of endpoints.
    * **`OverwriteOldHeader`**: Tests updating an existing header, including modifications and additions.
    * **`OverwriteOldHeaderWithCompletelyNew`**: Tests replacing an entire set of endpoint groups with a new set.
    * **`ZeroMaxAgeRemovesEndpointGroup`**: (In the provided snippet, this test is incomplete, but I infer its purpose). It likely tests that setting `max-age=0` for a reporting group removes it.

5. **Identify Key Concepts and Classes:**
    * `ReportingHeaderParser`: The class under test.
    * `ReportingCache`: The component where the parsed reporting information is stored.
    * `ReportingEndpointGroup`: Represents a group of reporting endpoints.
    * `ReportingEndpoint`: Represents a specific endpoint URL.
    * `ReportingPolicy`: Defines limits and constraints on reporting.
    * `NetworkAnonymizationKey` (NAK):  Used for privacy and isolation.
    * `url::Origin`: Represents the origin of the request.
    * `MockPersistentReportingStore`: A mock object used to verify interactions with persistent storage.
    * `CommandType`:  An enum representing the different operations performed on the persistent store (ADD, DELETE, UPDATE).

6. **Consider the Relationship to JavaScript:** While the core parsing happens in C++, the `Reporting` API is often triggered by JavaScript code running in the browser. Specifically, the `Report-To` header is set by the server, but JavaScript's `navigator.sendBeacon()` or `fetch()` API (with the `report-to` option) can interact with the reporting mechanism. I look for evidence of this connection, even if indirect in the unit test.

7. **Infer Logical Relationships (Input/Output):** For each test, I think about what the input header string would be and what the expected state of the `ReportingCache` should be after parsing. I also consider the commands sent to the `MockPersistentReportingStore`.

8. **Consider User/Programming Errors:**  I look for tests that specifically handle "erroneous" header formats. These highlight potential mistakes developers could make when configuring reporting.

9. **Trace User Operations (Debugging):**  I consider how a user action (e.g., visiting a website) could lead to the browser processing a `Report-To` header and invoking the parsing logic being tested. This helps establish the context for debugging.

10. **Synthesize the Functionality Summary:**  Based on the analysis of individual tests, I summarize the overall purpose of the code: testing the parsing of `Report-To` headers and the management of reporting endpoint groups and endpoints in the cache.

11. **Structure the Response:** I organize my findings into the requested categories: functionality, JavaScript relationship, logical inferences, user errors, debugging, and the overall summary. I use clear headings and bullet points for readability.

12. **Review and Refine:** I reread my analysis to ensure accuracy, clarity, and completeness, making sure to address all parts of the original request. I also pay attention to the "part 2 of 3" instruction, ensuring the summary reflects the specific code provided in this part.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive and informative response. The process involves understanding the code's purpose, dissecting its structure, identifying key concepts, and connecting it to the broader context of web development and debugging.
这是 Chromium 网络栈中 `net/reporting/reporting_header_parser_unittest.cc` 文件的第二部分代码。延续第一部分的分析，这部分代码继续测试 `ReportingHeaderParser` 类的功能，专注于解析 HTTP 响应头中的 `Report-To` 字段，并将解析结果存储到 `ReportingCache` 中。

以下是对这部分代码功能的归纳：

**主要功能：测试 `ReportingHeaderParser` 解析 `Report-To` 头的能力，并验证其与 `ReportingCache` 的交互。**

更具体地说，这部分测试涵盖了以下场景：

* **Endpoint Group Key 的独特性：** 验证即使 endpoint 的 URL 和 group name 相同，只要 NetworkAnonymizationKey (NAK) 或 Origin 不同，就会被视为不同的 endpoint group。这确保了不同上下文下的 reporting 配置不会互相干扰。
* **处理包含相同 Group Name 的多个组：** 测试当 `Report-To` 头中包含多个相同名字的 group 时，解析器的行为。预期行为是将这些组视为一个组，并合并其包含的 endpoints。这可以防止重复添加和简化处理逻辑。
* **处理包含冗余 Endpoint 的组：** 验证解析器能够去除同一 group 中重复的 endpoint URL，避免不必要的存储和处理。
* **处理包含相同 Group Name 和 Endpoint 的多个组：** 测试当多个相同名字的 group 中包含相同的 endpoint 时，解析器是否能够正确地去重。
* **处理包含相同 Group Name 但 Endpoint 重叠的多个组：** 验证当多个同名 group 包含部分相同的 endpoint 时，解析器会将所有不同的 endpoint 合并到同一个 group 中。
* **覆盖旧的 Header：** 测试当同一个 Origin 发送新的 `Report-To` 头时，旧的配置会被正确地覆盖。这包括更新已存在的 endpoint 的属性，删除不再存在的 endpoint，以及添加新的 endpoint 或 group。
* **用完全新的 Header 覆盖旧的 Header：** 测试用一个完全不同的 `Report-To` 头替换旧的配置，包括删除旧的 group 和 endpoint，并添加新的 group 和 endpoint。
* **`max-age: 0` 删除 Endpoint Group：** (虽然这部分代码片段结尾不完整，但从测试的命名可以推断) 测试当 `Report-To` 头中某个 group 的 `max-age` 设置为 0 时，该 group 会被从 `ReportingCache` 中移除。

**与 JavaScript 的关系：**

`Report-To` HTTP 响应头通常是由服务器设置的。当浏览器接收到包含 `Report-To` 头的响应时，网络栈会解析这个头部并将 reporting 配置存储起来。

与 JavaScript 的直接关系较少，因为这是 C++ 的网络栈代码。然而，JavaScript 可以通过以下方式间接影响：

* **服务器设置 `Report-To` 头：**  服务器端代码（例如 Node.js, Python 等）在处理用户请求时，可以设置 `Report-To` 头来指示浏览器将特定类型的错误或事件报告到指定的 endpoint。
* **JavaScript 触发的网络请求：**  JavaScript 代码（例如使用 `fetch` 或 `XMLHttpRequest`）发起的网络请求接收到包含 `Report-To` 头的响应时，会触发这里的解析逻辑。

**举例说明：**

假设一个网站的服务器返回以下 `Report-To` 头部：

```
Report-To: {"group":"errors","max_age":86400,"endpoints":[{"url":"https://example.com/report"}]}, {"group":"deprecation","max_age":604800,"endpoints":[{"url":"https://example.com/deprecation-report"}]}
```

当浏览器加载这个网站的页面时，`ReportingHeaderParser` 会解析这个头部，并在 `ReportingCache` 中创建两个 endpoint group：

* **Group "errors"**: 包含一个 endpoint `https://example.com/report`，有效期 86400 秒。
* **Group "deprecation"**: 包含一个 endpoint `https://example.com/deprecation-report`，有效期 604800 秒。

**逻辑推理、假设输入与输出：**

**测试 `EndpointGroupKey`:**

* **假设输入：**
    * 两个不同的 `NetworkAnonymizationKey` (`kNak_`, `kOtherNak_`)
    * 两个不同的 Origin (`kUrl1_`, `kUrl2_`)
    * 两个相同的 Group Name (`kGroup1_`, `kGroup2_`)
    * `Report-To` 头部字符串，包含以上不同组合的 endpoint group。
* **预期输出：** `ReportingCache` 中会创建四个不同的 endpoint group，每个 group 的 key 由 `(NetworkAnonymizationKey, Origin, Group Name)` 唯一确定。即使 endpoint URL 相同，由于 key 的不同，也会被视为不同的配置。

**测试 `HeaderErroneouslyContainsMultipleGroupsOfSameName`:**

* **假设输入：**
    * 一个 Origin (`kOrigin1_`)
    * 一个 Group Name (`kGroup1_`)
    * `Report-To` 头部字符串，包含两个相同名字的 group，但 endpoint 不同：
      ```
      Report-To: {"group":"group1","endpoints":[{"url":"https://a.com"}]}, {"group":"group1","endpoints":[{"url":"https://b.com"}]}
      ```
* **预期输出：** `ReportingCache` 中只会存在一个名为 "group1" 的 endpoint group，它包含了 `https://a.com` 和 `https://b.com` 两个 endpoint。

**用户或编程常见的使用错误：**

* **配置错误的 `Report-To` 头部格式：**  如果服务器返回的 `Report-To` 头部格式不符合规范（例如 JSON 格式错误，缺少必要的字段），`ReportingHeaderParser` 可能无法正确解析，导致 reporting 功能失效。
* **在多个响应中发送冲突的 `Report-To` 配置：**  如果服务器在不同的响应中发送具有相同 group name 但 endpoint 不同的 `Report-To` 头部，可能会导致客户端的 reporting 配置混乱。虽然测试表明解析器会合并，但最好避免这种情况以提高可预测性。
* **忘记设置 `max-age`：** 如果 `max-age` 没有设置，浏览器可能会缓存 reporting 配置很长时间，即使服务器已经更新了配置。

**用户操作如何到达这里（调试线索）：**

1. **用户访问网站：** 用户在浏览器地址栏输入网址或点击链接访问一个网站。
2. **服务器响应包含 `Report-To` 头：** 网站的服务器在 HTTP 响应头中设置了 `Report-To` 字段，指示浏览器如何进行错误或事件报告。
3. **浏览器接收响应：** 浏览器接收到服务器的响应。
4. **网络栈处理响应头：** 浏览器的网络栈开始解析接收到的 HTTP 响应头。
5. **`ReportingHeaderParser` 被调用：** 当网络栈遇到 `Report-To` 头部时，会调用 `ReportingHeaderParser` 来解析这个头部。
6. **解析结果存储到 `ReportingCache`：** `ReportingHeaderParser` 将解析得到的 endpoint group 和 endpoint 信息存储到 `ReportingCache` 中。
7. **后续的 Reporting 操作：** 当网站发生需要报告的事件时，浏览器会根据 `ReportingCache` 中存储的配置，将报告发送到指定的 endpoint。

在调试 reporting 相关问题时，可以检查以下方面：

* **服务器返回的 `Report-To` 头部是否正确。**
* **`ReportingCache` 中是否存储了预期的 endpoint group 和 endpoint 信息。**
* **网络请求是否成功发送到报告 endpoint。**

**总结：**

这部分代码主要测试了 `ReportingHeaderParser` 在解析各种复杂的 `Report-To` 头部时的行为，包括处理不同来源、不同命名、以及包含冗余或重复 endpoint 的情况。它验证了解析器能够正确地更新和覆盖已有的 reporting 配置，并确保了 reporting 配置的隔离性和正确性。  这对于确保浏览器能够按照服务器的指示进行有效的错误和事件报告至关重要。

### 提示词
```
这是目录为net/reporting/reporting_header_parser_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
s.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey21_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey22_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

// Test that each combination of NAK, origin, and group name is considered
// distinct.
// See also: ReportingCacheTest.ClientsKeyedByEndpointGroupKey
TEST_P(ReportingHeaderParserTest, EndpointGroupKey) {
  // Raise the endpoint limits for this test.
  ReportingPolicy policy;
  policy.max_endpoints_per_origin = 5;  // This test should use 4.
  policy.max_endpoint_count = 20;       // This test should use 16.
  UsePolicy(policy);

  std::vector<ReportingEndpoint::EndpointInfo> endpoints1 = {{kEndpoint1_},
                                                             {kEndpoint2_}};
  std::string header1 =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints1)) +
      ", " +
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup2_, endpoints1));

  const ReportingEndpointGroupKey kOtherGroupKey11 = ReportingEndpointGroupKey(
      kOtherNak_, kOrigin1_, kGroup1_, ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kOtherGroupKey21 = ReportingEndpointGroupKey(
      kOtherNak_, kOrigin2_, kGroup1_, ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kOtherGroupKey12 = ReportingEndpointGroupKey(
      kOtherNak_, kOrigin1_, kGroup2_, ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kOtherGroupKey22 = ReportingEndpointGroupKey(
      kOtherNak_, kOrigin2_, kGroup2_, ReportingTargetType::kDeveloper);

  const struct {
    NetworkAnonymizationKey network_anonymization_key;
    GURL url;
    ReportingEndpointGroupKey group1_key;
    ReportingEndpointGroupKey group2_key;
  } kHeaderSources[] = {
      {kNak_, kUrl1_, kGroupKey11_, kGroupKey12_},
      {kNak_, kUrl2_, kGroupKey21_, kGroupKey22_},
      {kOtherNak_, kUrl1_, kOtherGroupKey11, kOtherGroupKey12},
      {kOtherNak_, kUrl2_, kOtherGroupKey21, kOtherGroupKey22},
  };

  size_t endpoint_group_count = 0u;
  size_t endpoint_count = 0u;
  MockPersistentReportingStore::CommandList expected_commands;

  // Set 2 endpoints in each of 2 groups for each of 2x2 combinations of
  // (NAK, origin).
  for (const auto& source : kHeaderSources) {
    // Verify pre-parsing state
    EXPECT_FALSE(FindEndpointInCache(source.group1_key, kEndpoint1_));
    EXPECT_FALSE(FindEndpointInCache(source.group1_key, kEndpoint2_));
    EXPECT_FALSE(FindEndpointInCache(source.group2_key, kEndpoint1_));
    EXPECT_FALSE(FindEndpointInCache(source.group2_key, kEndpoint2_));
    EXPECT_FALSE(EndpointGroupExistsInCache(source.group1_key,
                                            OriginSubdomains::DEFAULT));
    EXPECT_FALSE(EndpointGroupExistsInCache(source.group2_key,
                                            OriginSubdomains::DEFAULT));

    ParseHeader(source.network_anonymization_key,
                url::Origin::Create(source.url), header1);
    endpoint_group_count += 2u;
    endpoint_count += 4u;
    EXPECT_EQ(endpoint_group_count, cache()->GetEndpointGroupCountForTesting());
    EXPECT_EQ(endpoint_count, cache()->GetEndpointCount());

    // Verify post-parsing state
    EXPECT_TRUE(FindEndpointInCache(source.group1_key, kEndpoint1_));
    EXPECT_TRUE(FindEndpointInCache(source.group1_key, kEndpoint2_));
    EXPECT_TRUE(FindEndpointInCache(source.group2_key, kEndpoint1_));
    EXPECT_TRUE(FindEndpointInCache(source.group2_key, kEndpoint2_));
    EXPECT_TRUE(EndpointGroupExistsInCache(source.group1_key,
                                           OriginSubdomains::DEFAULT));
    EXPECT_TRUE(EndpointGroupExistsInCache(source.group2_key,
                                           OriginSubdomains::DEFAULT));

    if (mock_store()) {
      mock_store()->Flush();
      EXPECT_EQ(static_cast<int>(endpoint_count),
                mock_store()->StoredEndpointsCount());
      EXPECT_EQ(static_cast<int>(endpoint_group_count),
                mock_store()->StoredEndpointGroupsCount());
      expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                     source.group1_key, kEndpoint1_);
      expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                     source.group1_key, kEndpoint2_);
      expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                     source.group1_key);
      expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                     source.group2_key, kEndpoint1_);
      expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                     source.group2_key, kEndpoint2_);
      expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                     source.group2_key);
      EXPECT_THAT(mock_store()->GetAllCommands(),
                  testing::IsSupersetOf(expected_commands));
    }
  }

  // Check that expected data is present in the ReportingCache at the end.
  for (const auto& source : kHeaderSources) {
    EXPECT_TRUE(FindEndpointInCache(source.group1_key, kEndpoint1_));
    EXPECT_TRUE(FindEndpointInCache(source.group1_key, kEndpoint2_));
    EXPECT_TRUE(FindEndpointInCache(source.group2_key, kEndpoint1_));
    EXPECT_TRUE(FindEndpointInCache(source.group2_key, kEndpoint2_));
    EXPECT_TRUE(EndpointGroupExistsInCache(source.group1_key,
                                           OriginSubdomains::DEFAULT));
    EXPECT_TRUE(EndpointGroupExistsInCache(source.group2_key,
                                           OriginSubdomains::DEFAULT));
    EXPECT_TRUE(cache()->ClientExistsForTesting(
        source.network_anonymization_key, url::Origin::Create(source.url)));
  }

  // Test updating existing configurations

  // This removes endpoint 1, updates the priority of endpoint 2, and adds
  // endpoint 3.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints2 = {{kEndpoint2_, 2},
                                                             {kEndpoint3_}};
  // Removes group 1, updates include_subdomains for group 2.
  std::string header2 = ConstructHeaderGroupString(
      MakeEndpointGroup(kGroup2_, endpoints2, OriginSubdomains::INCLUDE));

  for (const auto& source : kHeaderSources) {
    // Verify pre-update state
    EXPECT_TRUE(EndpointGroupExistsInCache(source.group1_key,
                                           OriginSubdomains::DEFAULT));
    EXPECT_TRUE(EndpointGroupExistsInCache(source.group2_key,
                                           OriginSubdomains::DEFAULT));
    EXPECT_TRUE(FindEndpointInCache(source.group2_key, kEndpoint1_));
    ReportingEndpoint endpoint =
        FindEndpointInCache(source.group2_key, kEndpoint2_);
    EXPECT_TRUE(endpoint);
    EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
              endpoint.info.priority);
    EXPECT_FALSE(FindEndpointInCache(source.group2_key, kEndpoint3_));

    ParseHeader(source.network_anonymization_key,
                url::Origin::Create(source.url), header2);
    endpoint_group_count--;
    endpoint_count -= 2;
    EXPECT_EQ(endpoint_group_count, cache()->GetEndpointGroupCountForTesting());
    EXPECT_EQ(endpoint_count, cache()->GetEndpointCount());

    // Verify post-update state
    EXPECT_FALSE(EndpointGroupExistsInCache(source.group1_key,
                                            OriginSubdomains::DEFAULT));
    EXPECT_TRUE(EndpointGroupExistsInCache(source.group2_key,
                                           OriginSubdomains::INCLUDE));
    EXPECT_FALSE(FindEndpointInCache(source.group2_key, kEndpoint1_));
    endpoint = FindEndpointInCache(source.group2_key, kEndpoint2_);
    EXPECT_TRUE(endpoint);
    EXPECT_EQ(2, endpoint.info.priority);
    EXPECT_TRUE(FindEndpointInCache(source.group2_key, kEndpoint3_));

    if (mock_store()) {
      mock_store()->Flush();
      EXPECT_EQ(static_cast<int>(endpoint_count),
                mock_store()->StoredEndpointsCount());
      EXPECT_EQ(static_cast<int>(endpoint_group_count),
                mock_store()->StoredEndpointGroupsCount());
      expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                     source.group1_key, kEndpoint1_);
      expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                     source.group1_key, kEndpoint2_);
      expected_commands.emplace_back(
          CommandType::DELETE_REPORTING_ENDPOINT_GROUP, source.group1_key);
      expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                     source.group2_key, kEndpoint1_);
      expected_commands.emplace_back(
          CommandType::UPDATE_REPORTING_ENDPOINT_DETAILS, source.group2_key,
          kEndpoint2_);
      expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                     source.group2_key, kEndpoint3_);
      expected_commands.emplace_back(
          CommandType::UPDATE_REPORTING_ENDPOINT_GROUP_DETAILS,
          source.group2_key);
      EXPECT_THAT(mock_store()->GetAllCommands(),
                  testing::IsSupersetOf(expected_commands));
    }
  }

  // Check that expected data is present in the ReportingCache at the end.
  for (const auto& source : kHeaderSources) {
    EXPECT_FALSE(FindEndpointInCache(source.group1_key, kEndpoint1_));
    EXPECT_FALSE(FindEndpointInCache(source.group1_key, kEndpoint2_));
    EXPECT_FALSE(FindEndpointInCache(source.group2_key, kEndpoint1_));
    EXPECT_TRUE(FindEndpointInCache(source.group2_key, kEndpoint2_));
    EXPECT_TRUE(FindEndpointInCache(source.group2_key, kEndpoint3_));
    EXPECT_FALSE(EndpointGroupExistsInCache(source.group1_key,
                                            OriginSubdomains::DEFAULT));
    EXPECT_TRUE(EndpointGroupExistsInCache(source.group2_key,
                                           OriginSubdomains::INCLUDE));
    EXPECT_TRUE(cache()->ClientExistsForTesting(
        source.network_anonymization_key, url::Origin::Create(source.url)));
  }
}

TEST_P(ReportingHeaderParserTest,
       HeaderErroneouslyContainsMultipleGroupsOfSameName) {
  // Add a preexisting header to test that a header with multiple groups of the
  // same name is treated as if it specified a single group with the combined
  // set of specified endpoints. In particular, it must overwrite/update any
  // preexisting group all at once. See https://crbug.com/1116529.
  std::vector<ReportingEndpoint::EndpointInfo> preexisting = {{kEndpoint1_}};
  std::string preexisting_header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, preexisting));

  ParseHeader(kNak_, kOrigin1_, preexisting_header);
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint = FindEndpointInCache(kGroupKey11_, kEndpoint1_);
  ASSERT_TRUE(endpoint);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(1, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
    // Reset commands so we can check that the next part, adding the header with
    // duplicate groups, does not cause clearing of preexisting endpoints twice.
    mock_store()->ClearCommands();
  }

  std::vector<ReportingEndpoint::EndpointInfo> endpoints1 = {{kEndpoint1_}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints2 = {{kEndpoint2_}};
  std::string duplicate_groups_header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints1)) +
      ", " +
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints2));

  ParseHeader(kNak_, kOrigin1_, duplicate_groups_header);
  // Result is as if they set the two groups with the same name as one group.
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));

  EXPECT_EQ(2u, cache()->GetEndpointCount());
  ReportingEndpoint endpoint1 = FindEndpointInCache(kGroupKey11_, kEndpoint1_);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kOrigin1_, endpoint.group_key.origin);
  EXPECT_EQ(kGroup1_, endpoint.group_key.group_name);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint.info.weight);

  ReportingEndpoint endpoint2 = FindEndpointInCache(kGroupKey11_, kEndpoint2_);
  ASSERT_TRUE(endpoint2);
  EXPECT_EQ(kOrigin1_, endpoint2.group_key.origin);
  EXPECT_EQ(kGroup1_, endpoint2.group_key.group_name);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultPriority,
            endpoint2.info.priority);
  EXPECT_EQ(ReportingEndpoint::EndpointInfo::kDefaultWeight,
            endpoint2.info.weight);

  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(2, mock_store()->StoredEndpointsCount());
    EXPECT_EQ(1, mock_store()->StoredEndpointGroupsCount());
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(
        CommandType::UPDATE_REPORTING_ENDPOINT_DETAILS, kGroupKey11_,
        kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint2_);
    expected_commands.emplace_back(
        CommandType::UPDATE_REPORTING_ENDPOINT_GROUP_DETAILS, kGroupKey11_);
    MockPersistentReportingStore::CommandList actual_commands =
        mock_store()->GetAllCommands();
    EXPECT_THAT(actual_commands, testing::IsSupersetOf(expected_commands));
    for (const auto& command : actual_commands) {
      EXPECT_NE(CommandType::DELETE_REPORTING_ENDPOINT, command.type);
      EXPECT_NE(CommandType::DELETE_REPORTING_ENDPOINT_GROUP, command.type);

      // The endpoint with URL kEndpoint1_ is only ever updated, not added anew.
      EXPECT_NE(
          MockPersistentReportingStore::Command(
              CommandType::ADD_REPORTING_ENDPOINT, kGroupKey11_, kEndpoint1_),
          command);
      // The group is only ever updated, not added anew.
      EXPECT_NE(MockPersistentReportingStore::Command(
                    CommandType::ADD_REPORTING_ENDPOINT_GROUP, kGroupKey11_),
                command);
    }
  }
}

TEST_P(ReportingHeaderParserTest,
       HeaderErroneouslyContainsGroupsWithRedundantEndpoints) {
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_},
                                                            {kEndpoint1_}};
  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints));
  ParseHeader(kNak_, kOrigin1_, header);

  // We should dedupe the identical endpoint URLs.
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  ASSERT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint1_));

  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
}

TEST_P(ReportingHeaderParserTest,
       HeaderErroneouslyContainsMultipleGroupsOfSameNameAndEndpoints) {
  std::vector<ReportingEndpoint::EndpointInfo> endpoints = {{kEndpoint1_}};
  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints)) +
      ", " + ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints));
  ParseHeader(kNak_, kOrigin1_, header);

  // We should dedupe the identical endpoint URLs, even when they're in
  // different group.
  EXPECT_EQ(1u, cache()->GetEndpointCount());
  ASSERT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint1_));

  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
}

TEST_P(ReportingHeaderParserTest,
       HeaderErroneouslyContainsGroupsOfSameNameAndOverlappingEndpoints) {
  std::vector<ReportingEndpoint::EndpointInfo> endpoints1 = {{kEndpoint1_},
                                                             {kEndpoint2_}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints2 = {{kEndpoint1_},
                                                             {kEndpoint3_}};
  std::string header =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints1)) +
      ", " +
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints2));
  ParseHeader(kNak_, kOrigin1_, header);

  // We should dedupe the identical endpoint URLs, even when they're in
  // different group.
  EXPECT_EQ(3u, cache()->GetEndpointCount());
  ASSERT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint1_));
  ASSERT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint2_));
  ASSERT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint3_));

  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
}

TEST_P(ReportingHeaderParserTest, OverwriteOldHeader) {
  // First, the origin sets a header with two endpoints in the same group.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints1 = {
      {kEndpoint1_, 10 /* priority */}, {kEndpoint2_}};
  std::string header1 =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints1));
  ParseHeader(kNak_, kOrigin1_, header1);

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_EQ(2u, cache()->GetEndpointCount());
  EXPECT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint1_));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint2_));
  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(2,
              mock_store()->CountCommands(CommandType::ADD_REPORTING_ENDPOINT));
    EXPECT_EQ(1, mock_store()->CountCommands(
                     CommandType::ADD_REPORTING_ENDPOINT_GROUP));
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint1_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint2_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey11_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }

  // Second header from the same origin should overwrite the previous one.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints2 = {
      // This endpoint should update the priority of the existing one.
      {kEndpoint1_, 20 /* priority */}};
  // The second endpoint in this group will be deleted.
  // This group is new.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints3 = {{kEndpoint2_}};
  std::string header2 =
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup1_, endpoints2)) +
      ", " +
      ConstructHeaderGroupString(MakeEndpointGroup(kGroup2_, endpoints3));
  ParseHeader(kNak_, kOrigin1_, header2);

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));

  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey12_, OriginSubdomains::DEFAULT));

  EXPECT_EQ(2u, cache()->GetEndpointCount());
  EXPECT_TRUE(FindEndpointInCache(kGroupKey11_, kEndpoint1_));
  EXPECT_EQ(20, FindEndpointInCache(kGroupKey11_, kEndpoint1_).info.priority);
  EXPECT_FALSE(FindEndpointInCache(kGroupKey11_, kEndpoint2_));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey12_, kEndpoint2_));
  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(2 + 1,
              mock_store()->CountCommands(CommandType::ADD_REPORTING_ENDPOINT));
    EXPECT_EQ(1 + 1, mock_store()->CountCommands(
                         CommandType::ADD_REPORTING_ENDPOINT_GROUP));
    EXPECT_EQ(
        1, mock_store()->CountCommands(CommandType::DELETE_REPORTING_ENDPOINT));
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey12_, kEndpoint2_);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey12_);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey11_, kEndpoint2_);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, OverwriteOldHeaderWithCompletelyNew) {
  ReportingEndpointGroupKey kGroupKey1(kNak_, kOrigin1_, "1",
                                       ReportingTargetType::kDeveloper);
  ReportingEndpointGroupKey kGroupKey2(kNak_, kOrigin1_, "2",
                                       ReportingTargetType::kDeveloper);
  ReportingEndpointGroupKey kGroupKey3(kNak_, kOrigin1_, "3",
                                       ReportingTargetType::kDeveloper);
  ReportingEndpointGroupKey kGroupKey4(kNak_, kOrigin1_, "4",
                                       ReportingTargetType::kDeveloper);
  ReportingEndpointGroupKey kGroupKey5(kNak_, kOrigin1_, "5",
                                       ReportingTargetType::kDeveloper);
  std::vector<ReportingEndpoint::EndpointInfo> endpoints1_1 = {{MakeURL(10)},
                                                               {MakeURL(11)}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints2_1 = {{MakeURL(20)},
                                                               {MakeURL(21)}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints3_1 = {{MakeURL(30)},
                                                               {MakeURL(31)}};
  std::string header1 =
      ConstructHeaderGroupString(MakeEndpointGroup("1", endpoints1_1)) + ", " +
      ConstructHeaderGroupString(MakeEndpointGroup("2", endpoints2_1)) + ", " +
      ConstructHeaderGroupString(MakeEndpointGroup("3", endpoints3_1));
  ParseHeader(kNak_, kOrigin1_, header1);
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(3u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey1, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey2, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey3, OriginSubdomains::DEFAULT));
  EXPECT_EQ(6u, cache()->GetEndpointCount());
  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(6,
              mock_store()->CountCommands(CommandType::ADD_REPORTING_ENDPOINT));
    EXPECT_EQ(3, mock_store()->CountCommands(
                     CommandType::ADD_REPORTING_ENDPOINT_GROUP));
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey1, endpoints1_1[0].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey1, endpoints1_1[1].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey2, endpoints2_1[0].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey2, endpoints2_1[1].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey3, endpoints3_1[0].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey3, endpoints3_1[1].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey1);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey2);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey3);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }

  // Replace endpoints in each group with completely new endpoints.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints1_2 = {{MakeURL(12)}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints2_2 = {{MakeURL(22)}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints3_2 = {{MakeURL(32)}};
  std::string header2 =
      ConstructHeaderGroupString(MakeEndpointGroup("1", endpoints1_2)) + ", " +
      ConstructHeaderGroupString(MakeEndpointGroup("2", endpoints2_2)) + ", " +
      ConstructHeaderGroupString(MakeEndpointGroup("3", endpoints3_2));
  ParseHeader(kNak_, kOrigin1_, header2);
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(3u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey1, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey2, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey3, OriginSubdomains::DEFAULT));
  EXPECT_EQ(3u, cache()->GetEndpointCount());
  EXPECT_TRUE(FindEndpointInCache(kGroupKey1, MakeURL(12)));
  EXPECT_FALSE(FindEndpointInCache(kGroupKey1, MakeURL(10)));
  EXPECT_FALSE(FindEndpointInCache(kGroupKey1, MakeURL(11)));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey2, MakeURL(22)));
  EXPECT_FALSE(FindEndpointInCache(kGroupKey2, MakeURL(20)));
  EXPECT_FALSE(FindEndpointInCache(kGroupKey2, MakeURL(21)));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey3, MakeURL(32)));
  EXPECT_FALSE(FindEndpointInCache(kGroupKey3, MakeURL(30)));
  EXPECT_FALSE(FindEndpointInCache(kGroupKey3, MakeURL(31)));
  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(6 + 3,
              mock_store()->CountCommands(CommandType::ADD_REPORTING_ENDPOINT));
    EXPECT_EQ(3, mock_store()->CountCommands(
                     CommandType::ADD_REPORTING_ENDPOINT_GROUP));
    EXPECT_EQ(
        6, mock_store()->CountCommands(CommandType::DELETE_REPORTING_ENDPOINT));
    EXPECT_EQ(0, mock_store()->CountCommands(
                     CommandType::DELETE_REPORTING_ENDPOINT_GROUP));
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey1, endpoints1_2[0].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey2, endpoints2_2[0].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey3, endpoints3_2[0].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey1, endpoints1_1[0].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey1, endpoints1_1[1].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey2, endpoints2_1[0].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey2, endpoints2_1[1].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey3, endpoints3_1[0].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey3, endpoints3_1[1].url);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }

  // Replace all the groups with completely new groups.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints4_3 = {{MakeURL(40)}};
  std::vector<ReportingEndpoint::EndpointInfo> endpoints5_3 = {{MakeURL(50)}};
  std::string header3 =
      ConstructHeaderGroupString(MakeEndpointGroup("4", endpoints4_3)) + ", " +
      ConstructHeaderGroupString(MakeEndpointGroup("5", endpoints5_3));
  ParseHeader(kNak_, kOrigin1_, header3);
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_EQ(2u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey4, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey4, OriginSubdomains::DEFAULT));
  EXPECT_FALSE(
      EndpointGroupExistsInCache(kGroupKey1, OriginSubdomains::DEFAULT));
  EXPECT_FALSE(
      EndpointGroupExistsInCache(kGroupKey2, OriginSubdomains::DEFAULT));
  EXPECT_FALSE(
      EndpointGroupExistsInCache(kGroupKey3, OriginSubdomains::DEFAULT));
  EXPECT_EQ(2u, cache()->GetEndpointCount());
  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(6 + 3 + 2,
              mock_store()->CountCommands(CommandType::ADD_REPORTING_ENDPOINT));
    EXPECT_EQ(3 + 2, mock_store()->CountCommands(
                         CommandType::ADD_REPORTING_ENDPOINT_GROUP));
    EXPECT_EQ(6 + 3, mock_store()->CountCommands(
                         CommandType::DELETE_REPORTING_ENDPOINT));
    EXPECT_EQ(3, mock_store()->CountCommands(
                     CommandType::DELETE_REPORTING_ENDPOINT_GROUP));
    MockPersistentReportingStore::CommandList expected_commands;
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey4, endpoints4_3[0].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT,
                                   kGroupKey5, endpoints5_3[0].url);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey4);
    expected_commands.emplace_back(CommandType::ADD_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey5);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey1, endpoints1_2[0].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey2, endpoints2_2[0].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT,
                                   kGroupKey3, endpoints3_2[0].url);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey1);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey2);
    expected_commands.emplace_back(CommandType::DELETE_REPORTING_ENDPOINT_GROUP,
                                   kGroupKey3);
    EXPECT_THAT(mock_store()->GetAllCommands(),
                testing::IsSupersetOf(expected_commands));
  }
}

TEST_P(ReportingHeaderParserTest, ZeroMaxAgeRemovesEndpointGroup) {
  // Without a pre-existing client, max_age: 0 should do nothing.
  ASSERT_EQ(0u, cache()->GetEndpointCount());
  ParseHeader(kNak_, kOrigin1_,
              "{\"endpoints\":[{\"url\":\"" + kEndpoint1_.spec() +
                  "\"}],\"max_age\":0}");
  EXPECT_EQ(0u, cache()->GetEndpointCount());
  if (mock_store()) {
    mock_store()->Flush();
    EXPECT_EQ(0,
              mock_store()->CountCommands(CommandType::ADD_REPORTING_ENDPOINT));
    EXPECT_EQ(0, mock_store()->CountCommands(
                     CommandType::ADD_REPORTING_ENDPOINT_GROUP));
  }

  // Set a header with two endpoint groups.
  std::vector<ReportingEndpoint::EndpointInfo> endpoints1 = {{kEndpoint1_}};
  std::vector<ReportingEndpoint::EndpointInf
```