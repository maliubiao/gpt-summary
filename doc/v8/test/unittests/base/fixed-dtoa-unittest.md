Response: The user wants to understand the functionality of the C++ code in `v8/test/unittests/base/fixed-dtoa-unittest.cc`. I need to analyze the code and provide a summary of its purpose. Since the filename includes "dtoa", I suspect it's related to converting double-precision floating-point numbers to strings. The "unittest" part indicates it's a test file.

Therefore, the main function of this file is to test the `FastFixedDtoa` function. It checks various double values and expected string representations after applying `FastFixedDtoa`.

The user also asks if there's a relation to JavaScript. V8 is the JavaScript engine used in Chrome and Node.js, so any code within V8's repository likely has a connection to JavaScript's functionality. Specifically, converting numbers to strings is a common operation in JavaScript.

To illustrate the connection, I can provide JavaScript examples that demonstrate similar number-to-string conversions and highlight how the `FastFixedDtoa` function might be involved behind the scenes. I should focus on scenarios where the number of decimal places is controlled, mirroring the `FastFixedDtoa` function's parameters.这个C++源代码文件 `fixed-dtoa-unittest.cc` 的主要功能是 **测试 V8 引擎中用于将双精度浮点数（double）快速转换为固定精度字符串的函数 `FastFixedDtoa` 的正确性**。

具体来说，这个文件包含了一系列的单元测试用例，这些用例覆盖了各种不同的双精度浮点数及其期望的字符串表示形式。每个测试用例都会调用 `FastFixedDtoa` 函数，并断言其输出结果（生成的字符串、小数点位置等）与预期的结果是否一致。

**与 JavaScript 的功能关系：**

V8 是 Google Chrome 浏览器和 Node.js 环境所使用的 JavaScript 引擎。因此，`FastFixedDtoa` 函数在 V8 中扮演着将 JavaScript 中的数字类型（Number）转换为字符串的重要角色。

在 JavaScript 中，当我们尝试将一个数字转换为字符串，并需要控制小数点后的位数时，V8 引擎内部可能会使用类似 `FastFixedDtoa` 这样的函数来实现。

**JavaScript 示例：**

以下 JavaScript 示例展示了与 `FastFixedDtoa` 功能相关的场景：

```javascript
// 将数字格式化为指定小数位数的字符串

let num = 1.23456;

// toFixed() 方法将数字转换为字符串，并保留指定位数的小数
let fixedString = num.toFixed(2);
console.log(fixedString); // 输出 "1.23"

let anotherNum = 0.0001;
let anotherFixedString = anotherNum.toFixed(5);
console.log(anotherFixedString); // 输出 "0.00010"

let largeNum = 123456789;
let largeFixedString = largeNum.toFixed(0);
console.log(largeFixedString); // 输出 "123456789"
```

**解释：**

*   **`toFixed(n)` 方法：** JavaScript 的 `Number.prototype.toFixed(n)` 方法与 `FastFixedDtoa` 的功能非常相似。它将一个数字转换为字符串，并将其小数点后的位数固定为 `n` 位。
*   **幕后工作：**  当 JavaScript 引擎执行 `toFixed()` 方法时，V8 内部可能会调用类似 `FastFixedDtoa` 这样的底层 C++ 函数来高效地完成数字到字符串的转换，并确保精度和性能。
*   **`FastFixedDtoa` 的参数：**  从测试代码中可以看出，`FastFixedDtoa` 函数接收以下关键参数：
    *   要转换的 `double` 值。
    *   期望的小数点后的位数。
    *   用于存储结果的字符缓冲区。
    *   用于返回生成字符串长度的指针。
    *   用于返回小数点位置的指针。

**总结：**

`fixed-dtoa-unittest.cc` 文件通过测试用例验证了 V8 引擎中 `FastFixedDtoa` 函数将双精度浮点数转换为指定精度字符串的功能是否正确。这个功能在 JavaScript 中对应于 `Number.prototype.toFixed()` 等方法，V8 引擎在底层可能使用类似 `FastFixedDtoa` 的高效算法来实现数字到字符串的转换。这个测试文件确保了 V8 引擎在处理 JavaScript 数字到字符串的转换时能够产生准确的结果。

Prompt: 
```
这是目录为v8/test/unittests/base/fixed-dtoa-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2010 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "src/base/numbers/fixed-dtoa.h"

#include <stdlib.h>

#include "test/unittests/gay-fixed.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

using FixedDtoaTest = ::testing::Test;
namespace base {

static const int kBufferSize = 500;

TEST_F(FixedDtoaTest, FastFixedVariousDoubles) {
  char buffer_container[kBufferSize];
  Vector<char> buffer(buffer_container, kBufferSize);
  int length;
  int point;

  CHECK(FastFixedDtoa(1.0, 1, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(1.0, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(1.0, 0, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0xFFFFFFFF, 5, buffer, &length, &point));
  CHECK_EQ(0, strcmp("4294967295", buffer.begin()));
  CHECK_EQ(10, point);

  CHECK(FastFixedDtoa(4294967296.0, 5, buffer, &length, &point));
  CHECK_EQ(0, strcmp("4294967296", buffer.begin()));
  CHECK_EQ(10, point);

  CHECK(FastFixedDtoa(1e21, 5, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  // CHECK_EQ(22, point);
  CHECK_EQ(22, point);

  CHECK(FastFixedDtoa(999999999999999868928.00, 2, buffer, &length, &point));
  CHECK_EQ(0, strcmp("999999999999999868928", buffer.begin()));
  CHECK_EQ(21, point);

  CHECK(FastFixedDtoa(6.9999999999999989514240000e+21, 5, buffer, &length,
                      &point));
  CHECK_EQ(0, strcmp("6999999999999998951424", buffer.begin()));
  CHECK_EQ(22, point);

  CHECK(FastFixedDtoa(1.5, 5, buffer, &length, &point));
  CHECK_EQ(0, strcmp("15", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(1.55, 5, buffer, &length, &point));
  CHECK_EQ(0, strcmp("155", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(1.55, 1, buffer, &length, &point));
  CHECK_EQ(0, strcmp("16", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(1.00000001, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("100000001", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.1, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(0, point);

  CHECK(FastFixedDtoa(0.01, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-1, point);

  CHECK(FastFixedDtoa(0.001, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-2, point);

  CHECK(FastFixedDtoa(0.0001, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-3, point);

  CHECK(FastFixedDtoa(0.00001, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-4, point);

  CHECK(FastFixedDtoa(0.000001, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-5, point);

  CHECK(FastFixedDtoa(0.0000001, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-6, point);

  CHECK(FastFixedDtoa(0.00000001, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-7, point);

  CHECK(FastFixedDtoa(0.000000001, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-8, point);

  CHECK(FastFixedDtoa(0.0000000001, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-9, point);

  CHECK(FastFixedDtoa(0.00000000001, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-10, point);

  CHECK(FastFixedDtoa(0.000000000001, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-11, point);

  CHECK(FastFixedDtoa(0.0000000000001, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-12, point);

  CHECK(FastFixedDtoa(0.00000000000001, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-13, point);

  CHECK(FastFixedDtoa(0.000000000000001, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-14, point);

  CHECK(FastFixedDtoa(0.0000000000000001, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-15, point);

  CHECK(FastFixedDtoa(0.00000000000000001, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-16, point);

  CHECK(FastFixedDtoa(0.000000000000000001, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-17, point);

  CHECK(FastFixedDtoa(0.0000000000000000001, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-18, point);

  CHECK(FastFixedDtoa(0.00000000000000000001, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-19, point);

  CHECK(FastFixedDtoa(0.10000000004, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(0, point);

  CHECK(FastFixedDtoa(0.01000000004, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-1, point);

  CHECK(FastFixedDtoa(0.00100000004, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-2, point);

  CHECK(FastFixedDtoa(0.00010000004, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-3, point);

  CHECK(FastFixedDtoa(0.00001000004, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-4, point);

  CHECK(FastFixedDtoa(0.00000100004, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-5, point);

  CHECK(FastFixedDtoa(0.00000010004, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-6, point);

  CHECK(FastFixedDtoa(0.00000001004, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-7, point);

  CHECK(FastFixedDtoa(0.00000000104, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-8, point);

  CHECK(FastFixedDtoa(0.0000000001000004, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-9, point);

  CHECK(FastFixedDtoa(0.0000000000100004, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-10, point);

  CHECK(FastFixedDtoa(0.0000000000010004, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-11, point);

  CHECK(FastFixedDtoa(0.0000000000001004, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-12, point);

  CHECK(FastFixedDtoa(0.0000000000000104, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-13, point);

  CHECK(FastFixedDtoa(0.000000000000001000004, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-14, point);

  CHECK(FastFixedDtoa(0.000000000000000100004, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-15, point);

  CHECK(FastFixedDtoa(0.000000000000000010004, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-16, point);

  CHECK(FastFixedDtoa(0.000000000000000001004, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-17, point);

  CHECK(FastFixedDtoa(0.000000000000000000104, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-18, point);

  CHECK(FastFixedDtoa(0.000000000000000000014, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-19, point);

  CHECK(FastFixedDtoa(0.10000000006, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1000000001", buffer.begin()));
  CHECK_EQ(0, point);

  CHECK(FastFixedDtoa(0.01000000006, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("100000001", buffer.begin()));
  CHECK_EQ(-1, point);

  CHECK(FastFixedDtoa(0.00100000006, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("10000001", buffer.begin()));
  CHECK_EQ(-2, point);

  CHECK(FastFixedDtoa(0.00010000006, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1000001", buffer.begin()));
  CHECK_EQ(-3, point);

  CHECK(FastFixedDtoa(0.00001000006, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("100001", buffer.begin()));
  CHECK_EQ(-4, point);

  CHECK(FastFixedDtoa(0.00000100006, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("10001", buffer.begin()));
  CHECK_EQ(-5, point);

  CHECK(FastFixedDtoa(0.00000010006, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1001", buffer.begin()));
  CHECK_EQ(-6, point);

  CHECK(FastFixedDtoa(0.00000001006, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("101", buffer.begin()));
  CHECK_EQ(-7, point);

  CHECK(FastFixedDtoa(0.00000000106, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("11", buffer.begin()));
  CHECK_EQ(-8, point);

  CHECK(FastFixedDtoa(0.0000000001000006, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("100001", buffer.begin()));
  CHECK_EQ(-9, point);

  CHECK(FastFixedDtoa(0.0000000000100006, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("10001", buffer.begin()));
  CHECK_EQ(-10, point);

  CHECK(FastFixedDtoa(0.0000000000010006, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1001", buffer.begin()));
  CHECK_EQ(-11, point);

  CHECK(FastFixedDtoa(0.0000000000001006, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("101", buffer.begin()));
  CHECK_EQ(-12, point);

  CHECK(FastFixedDtoa(0.0000000000000106, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("11", buffer.begin()));
  CHECK_EQ(-13, point);

  CHECK(FastFixedDtoa(0.000000000000001000006, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("100001", buffer.begin()));
  CHECK_EQ(-14, point);

  CHECK(FastFixedDtoa(0.000000000000000100006, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("10001", buffer.begin()));
  CHECK_EQ(-15, point);

  CHECK(FastFixedDtoa(0.000000000000000010006, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1001", buffer.begin()));
  CHECK_EQ(-16, point);

  CHECK(FastFixedDtoa(0.000000000000000001006, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("101", buffer.begin()));
  CHECK_EQ(-17, point);

  CHECK(FastFixedDtoa(0.000000000000000000106, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("11", buffer.begin()));
  CHECK_EQ(-18, point);

  CHECK(FastFixedDtoa(0.000000000000000000016, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("2", buffer.begin()));
  CHECK_EQ(-19, point);

  CHECK(FastFixedDtoa(0.6, 0, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.96, 1, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.996, 2, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.9996, 3, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.99996, 4, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.999996, 5, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.9999996, 6, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.99999996, 7, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.999999996, 8, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.9999999996, 9, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.99999999996, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.999999999996, 11, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.9999999999996, 12, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.99999999999996, 13, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.999999999999996, 14, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.9999999999999996, 15, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(0.00999999999999996, 16, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-1, point);

  CHECK(FastFixedDtoa(0.000999999999999996, 17, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-2, point);

  CHECK(FastFixedDtoa(0.0000999999999999996, 18, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-3, point);

  CHECK(FastFixedDtoa(0.00000999999999999996, 19, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-4, point);

  CHECK(FastFixedDtoa(0.000000999999999999996, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-5, point);

  CHECK(FastFixedDtoa(323423.234234, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("323423234234", buffer.begin()));
  CHECK_EQ(6, point);

  CHECK(FastFixedDtoa(12345678.901234, 4, buffer, &length, &point));
  CHECK_EQ(0, strcmp("123456789012", buffer.begin()));
  CHECK_EQ(8, point);

  CHECK(FastFixedDtoa(98765.432109, 5, buffer, &length, &point));
  CHECK_EQ(0, strcmp("9876543211", buffer.begin()));
  CHECK_EQ(5, point);

  CHECK(FastFixedDtoa(42, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("42", buffer.begin()));
  CHECK_EQ(2, point);

  CHECK(FastFixedDtoa(0.5, 0, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(1, point);

  CHECK(FastFixedDtoa(1e-23, 10, buffer, &length, &point));
  CHECK_EQ(0, strcmp("", buffer.begin()));
  CHECK_EQ(-10, point);

  CHECK(FastFixedDtoa(1e-123, 2, buffer, &length, &point));
  CHECK_EQ(0, strcmp("", buffer.begin()));
  CHECK_EQ(-2, point);

  CHECK(FastFixedDtoa(1e-123, 0, buffer, &length, &point));
  CHECK_EQ(0, strcmp("", buffer.begin()));
  CHECK_EQ(0, point);

  CHECK(FastFixedDtoa(1e-23, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("", buffer.begin()));
  CHECK_EQ(-20, point);

  CHECK(FastFixedDtoa(1e-21, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("", buffer.begin()));
  CHECK_EQ(-20, point);

  CHECK(FastFixedDtoa(1e-22, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("", buffer.begin()));
  CHECK_EQ(-20, point);

  CHECK(FastFixedDtoa(6e-21, 20, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1", buffer.begin()));
  CHECK_EQ(-19, point);

  CHECK(FastFixedDtoa(9.1193616301674545152000000e+19, 0, buffer, &length,
                      &point));
  CHECK_EQ(0, strcmp("91193616301674545152", buffer.begin()));
  CHECK_EQ(20, point);

  CHECK(FastFixedDtoa(4.8184662102767651659096515e-04, 19, buffer, &length,
                      &point));
  CHECK_EQ(0, strcmp("4818466210276765", buffer.begin()));
  CHECK_EQ(-3, point);

  CHECK(FastFixedDtoa(1.9023164229540652612705182e-23, 8, buffer, &length,
                      &point));
  CHECK_EQ(0, strcmp("", buffer.begin()));
  CHECK_EQ(-8, point);

  CHECK(FastFixedDtoa(1000000000000000128.0, 0, buffer, &length, &point));
  CHECK_EQ(0, strcmp("1000000000000000128", buffer.begin()));
  CHECK_EQ(19, point);
}

TEST_F(FixedDtoaTest, FastFixedDtoaGayFixed) {
  char buffer_container[kBufferSize];
  Vector<char> buffer(buffer_container, kBufferSize);
  bool status;
  int length;
  int point;

  Vector<const PrecomputedFixed> precomputed =
      PrecomputedFixedRepresentations();
  for (int i = 0; i < precomputed.length(); ++i) {
    const PrecomputedFixed current_test = precomputed[i];
    double v = current_test.v;
    int number_digits = current_test.number_digits;
    status = FastFixedDtoa(v, number_digits, buffer, &length, &point);
    CHECK(status);
    CHECK_EQ(current_test.decimal_point, point);
    CHECK_GE(number_digits, length - point);
    CHECK_EQ(0, strcmp(current_test.representation, buffer.begin()));
  }
}

}  // namespace base
}  // namespace v8

"""

```