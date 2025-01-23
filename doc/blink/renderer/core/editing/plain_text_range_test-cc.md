Response:

### 提示词
```
这是目录为blink/renderer/core/editing/plain_text_range_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/editing/plain_text_range.h"

#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"

namespace blink {

class PlainTextRangeTest : public EditingTestBase {};

TEST_F(PlainTextRangeTest, RangeContainingTableCellBoundary) {
  SetBodyInnerHTML(
      "<table id='sample' contenteditable><tr><td>a</td><td "
      "id='td2'>b</td></tr></table>");
  Element* table = GetElementById("sample");

  PlainTextRange plain_text_range(2, 2);
  const EphemeralRange& range = plain_text_range.CreateRange(*table);
  EXPECT_EQ(
      "<table contenteditable id=\"sample\"><tbody><tr><td>a</td><td "
      "id=\"td2\">|b</td></tr></tbody></table>",
      GetCaretTextFromBody(range.StartPosition()));
  EXPECT_TRUE(range.IsCollapsed());
}

}  // namespace blink
```