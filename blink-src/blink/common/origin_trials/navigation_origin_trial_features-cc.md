Response: 
Prompt: 
```
这是目录为blink/common/origin_trials/navigation_origin_trial_features.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file provides FeatureEnabledForNavigation which is declared in
// origin_trials.h. FeatureEnabledForNavigation is defined in this file since
// changes to it require review from security reviewers, listed in the
// SECURITY_OWNERS file.

#include "base/containers/contains.h"
#include "third_party/blink/public/common/origin_trials/origin_trials.h"
#include "third_party/blink/public/mojom/origin_trials/origin_trial_feature.mojom-shared.h"

namespace blink {

namespace origin_trials {

bool FeatureEnabledForNavigation(blink::mojom::OriginTrialFeature feature) {
  static blink::mojom::OriginTrialFeature const kEnabledForNavigation[] = {
      // Enable the kOriginTrialsSampleAPINavigation feature as a navigation
      // feature, for tests.
      blink::mojom::OriginTrialFeature::kOriginTrialsSampleAPINavigation,
      blink::mojom::OriginTrialFeature::kTextFragmentIdentifiers,
  };
  return base::Contains(kEnabledForNavigation, feature);
}

}  // namespace origin_trials

}  // namespace blink

"""

```