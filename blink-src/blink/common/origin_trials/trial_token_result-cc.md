Response: 
Prompt: 
```
这是目录为blink/common/origin_trials/trial_token_result.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/origin_trials/trial_token_result.h"

#include "third_party/blink/public/common/origin_trials/trial_token.h"

namespace blink {

TrialTokenResult::TrialTokenResult(OriginTrialTokenStatus status)
    : status_(status), parsed_token_(nullptr) {
  DCHECK(status_ != OriginTrialTokenStatus::kSuccess);
}
TrialTokenResult::TrialTokenResult(OriginTrialTokenStatus status,
                                   std::unique_ptr<TrialToken> parsed_token)
    : status_(status), parsed_token_(std::move(parsed_token)) {
  DCHECK(parsed_token_);
}

}  // namespace blink

"""

```