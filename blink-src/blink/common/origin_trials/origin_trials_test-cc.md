Response: 
Prompt: 
```
这是目录为blink/common/origin_trials/origin_trials_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/origin_trials/origin_trials.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace blink {
namespace {

const char kFrobulateTrialName[] = "Frobulate";
const char kFrobulateDeprecationTrialName[] = "FrobulateDeprecation";
const char kFrobulateThirdPartyTrialName[] = "FrobulateThirdParty";
const char kFrobulatePersistentTrialName[] = "FrobulatePersistent";

}  // namespace

TEST(OriginTrialTest, TrialsValid) {
  EXPECT_TRUE(origin_trials::IsTrialValid(kFrobulateTrialName));
  EXPECT_TRUE(origin_trials::IsTrialValid(kFrobulateThirdPartyTrialName));
}

TEST(OriginTrialTest, TrialEnabledForInsecureContext) {
  EXPECT_FALSE(
      origin_trials::IsTrialEnabledForInsecureContext(kFrobulateTrialName));
  EXPECT_TRUE(origin_trials::IsTrialEnabledForInsecureContext(
      kFrobulateDeprecationTrialName));
  EXPECT_FALSE(origin_trials::IsTrialEnabledForInsecureContext(
      kFrobulateThirdPartyTrialName));
}

TEST(OriginTrialTest, TrialsEnabledForThirdPartyOrigins) {
  EXPECT_FALSE(
      origin_trials::IsTrialEnabledForThirdPartyOrigins(kFrobulateTrialName));
  EXPECT_TRUE(origin_trials::IsTrialEnabledForThirdPartyOrigins(
      kFrobulateThirdPartyTrialName));
}

TEST(OriginTrialTest, TrialIsPersistent) {
  EXPECT_FALSE(
      origin_trials::IsTrialPersistentToNextResponse(kFrobulateTrialName));
  EXPECT_TRUE(origin_trials::IsTrialPersistentToNextResponse(
      kFrobulatePersistentTrialName));
}

}  // namespace blink

"""

```