Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of a unit test for a `Bignum` class in the V8 JavaScript engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core subject:** The code is a unit test file named `bignum-unittest.cc`. This immediately tells us that it's testing the functionalities of a class named `Bignum`.

2. **Analyze the test structure:**  The code uses the Google Test framework (`TEST_F`). Each `TEST_F` defines a specific test case for the `BignumTest` fixture. This means each test case focuses on testing a particular aspect or method of the `Bignum` class.

3. **Examine individual test cases:** Go through each `TEST_F` block and understand what it's testing:
    * `Assign`:  Tests assigning values to `Bignum` objects using different methods like `AssignUInt64`, `AssignHexString`, and checking the output using `ToHexString`.
    * `AssignPowerOfTen`:  Tests assigning a value and then multiplying it by powers of ten, verifying the results.
    * `MultiplyByUInt32`: Tests multiplying a `Bignum` by a 32-bit unsigned integer.
    * `MultiplyByBignum`: Tests multiplying two `Bignum` objects.
    * `ShiftLeft`: Tests left-shifting a `Bignum` by a specified number of bits.
    * `AddBignum`: Tests adding two `Bignum` objects.
    * `SubtractBignum`: Tests subtracting one `Bignum` from another.
    * `DivideModuloIntBignum`: Tests dividing a `Bignum` by another and getting the integer quotient, with the remainder left in the first `Bignum`.
    * `Compare`: Tests various comparison methods (`Compare`, `Equal`, `LessEqual`, `Less`) between two `Bignum` objects.
    * `PlusCompare`: Tests comparing the sum of two `Bignum` objects to a third `Bignum` using `PlusCompare`, `PlusEqual`, `PlusLessEqual`, and `PlusLess`.
    * `Square`: Tests squaring a `Bignum`.
    * `AssignPowerUInt16`: Tests assigning a `Bignum` the value of an unsigned 16-bit integer raised to a power.

4. **Identify common patterns and helper functions:** Notice the repeated usage of:
    * `Bignum` objects.
    * `Assign...` methods for setting values.
    * `ToHexString` for getting the hexadecimal representation.
    * `EXPECT_...` macros from Google Test for assertions.
    * `strcmp` for comparing strings (hexadecimal representations).
    * `AssignHexString` (though not a standard `Bignum` method, it's used for setting values from hex strings).

5. **Consider the context:** The code is in `v8/test/unittests/base/`. This confirms that it's a low-level unit test within the V8 engine, specifically targeting the `base` library, which likely contains foundational data structures and algorithms.

6. **Address specific instructions:**
    * **`.tq` extension:** The code is in `.cc`, not `.tq`, so it's not Torque.
    * **Relationship to JavaScript:** `Bignum` likely handles large integers needed for JavaScript number representation, especially for integers outside the safe integer range.
    * **Code examples:** Provide JavaScript examples that would benefit from a `Bignum` implementation (large integers).
    * **Logic inference (input/output):** For some tests, specific input values and expected hexadecimal outputs are provided in the `EXPECT_EQ(0, strcmp(...))` calls. Use these as examples.
    * **Common programming errors:** Think about errors related to handling large numbers (overflow, precision loss).

7. **Structure the summary:** Organize the findings into a coherent summary that addresses the user's request, including:
    * Overall purpose of the file.
    * Functionality of the tested class (`Bignum`).
    * Description of each test case.
    * Answers to the specific questions about `.tq`, JavaScript relationship, examples, and common errors.

8. **Refine the language:** Ensure the summary is clear, concise, and uses appropriate technical terms. For the "归纳一下它的功能" (summarize its functionality for the second part), focus on the operations demonstrated in the provided code snippet. This part deals with multiplication by powers of ten, division with modulo, and various comparison operations.
这是第2部分，继续归纳 `v8/test/unittests/base/bignum-unittest.cc` 的功能，基于你提供的代码片段：

**归纳 `v8/test/unittests/base/bignum-unittest.cc` (第 2 部分) 的功能:**

这部分代码主要集中在测试 `v8::base::Bignum` 类的以下功能：

1. **乘以 10 的幂 (MultiplyByPowerOfTen):**  测试将 `Bignum` 对象乘以 10 的不同幂次方（5, 10, 50, 100, 200, 500）后，其十六进制表示是否与预期相符。这对于处理十进制大数非常重要。

2. **带模除法 (DivideModuloIntBignum):** 测试将一个 `Bignum` 对象除以另一个 `Bignum` 对象，并返回整数商。同时，被除数对象会更新为余数。测试用例覆盖了不同的场景，包括：
    * 小数除法
    * 左右操作数都进行左移后的除法
    * 除数为 1 的情况
    * 被除数和除数非常接近的情况
    * 除法后余数的情况

3. **比较运算 (Compare):**  测试 `Bignum` 对象的比较功能，包括：
    * `Compare`: 返回 -1, 0 或 1，表示小于、等于或大于。
    * `Equal`: 判断两个 `Bignum` 是否相等。
    * `LessEqual`: 判断一个 `Bignum` 是否小于等于另一个。
    * `Less`: 判断一个 `Bignum` 是否小于另一个。
    测试用例覆盖了大小相等、大小不等、通过左移增加大小等多种情况。

4. **加法比较运算 (PlusCompare):** 测试将两个 `Bignum` 对象相加的结果与第三个 `Bignum` 对象进行比较的功能，包括：
    * `PlusCompare`: 返回 -1, 0 或 1，表示和小于、等于或大于第三个数。
    * `PlusEqual`: 判断和是否等于第三个数。
    * `PlusLessEqual`: 判断和是否小于等于第三个数。
    * `PlusLess`: 判断和是否小于第三个数。
    测试用例覆盖了各种加法和比较的场景，包括进位、不同数量级的数字等。

5. **平方运算 (Square):** 测试计算 `Bignum` 对象的平方值的功能。测试用例包括小的整数以及接近最大值的十六进制数。

6. **赋值为整数的幂 (AssignPowerUInt16):** 测试将 `Bignum` 对象赋值为一个无符号 16 位整数的指定次幂的功能。测试用例覆盖了不同的底数和指数，包括 1 的幂、不同大小的底数、以及 0 指数的情况。

**总结来说，这部分代码专注于测试 `Bignum` 类在进行算术运算（特别是与 10 的幂的乘法和带模除法）、比较运算（直接比较和加法比较）以及幂运算方面的正确性。**  这些功能是实现任意精度算术的关键组成部分。

**与 JavaScript 的关系 (补充说明):**

虽然这段 C++ 代码本身不是 JavaScript，但 `v8::base::Bignum` 类在 V8 引擎中扮演着至关重要的角色，因为它用于处理 JavaScript 中超出标准 IEEE 754 双精度浮点数安全整数范围的整数。

**JavaScript 例子 (补充说明):**

```javascript
// JavaScript 中超出安全整数范围的整数
const largeNumber1 = 9007199254740991n + 1n;
const largeNumber2 = 9007199254740992n;

// 在 JavaScript 中进行大数比较
console.log(largeNumber1 < largeNumber2); // 输出: true

// 模拟 Bignum 的 MultiplyByPowerOfTen 功能 (虽然 JavaScript 有 BigInt，但概念类似)
let num = 123n;
let powerOfTen = 1000n;
let result = num * powerOfTen;
console.log(result); // 输出: 123000n

// 模拟 Bignum 的 DivideModuloIntBignum 功能 (使用 BigInt 的 % 运算符)
let dividend = 100n;
let divisor = 3n;
let quotient = dividend / divisor;
let remainder = dividend % divisor;
console.log("商:", quotient);   // 输出: 商: 33n
console.log("余数:", remainder); // 输出: 余数: 1n
```

在 JavaScript 中，`BigInt` 类型允许进行任意精度的整数运算。V8 的 `Bignum` 类是其底层实现的一部分，负责处理这些大数的存储和运算。

**常见的编程错误 (补充说明):**

* **整数溢出:** 在传统的固定大小的整数类型中，进行超过其表示范围的运算会导致溢出，产生意想不到的结果。`Bignum` 的出现就是为了避免这种错误。
* **精度丢失:** 在 JavaScript 中使用浮点数表示大整数时，可能会因为浮点数的精度限制而导致精度丢失。`Bignum` 提供了精确的整数表示。
* **类型错误:**  在进行大数运算时，如果混合使用普通数字和 `BigInt`，可能会导致类型错误。需要确保操作数都是 `BigInt` 类型才能进行 `BigInt` 运算。

**假设输入与输出 (代码逻辑推理):**

**MultiplyByPowerOfTen 测试:**

* **假设输入:** `bignum2` 初始化为某个大数（例如，十六进制 "1815699B31E30B3CDFBE17D185F44910BBBF313896C3DC95B4B9314D19B5B32F57AD71655476B630F3E02DF855502394A74115A5BA2B480BCBCD5F52F6F69DE6C5622CB5152A54788BD9D14B896DE8CB73B53C3800DDACC9C51E0C38FAE762F9964232872F9C2738E7150C4AE3F1B18F70583172706FAEE26DC5A78C77A2FAA874769E52C01DA5C3499F233ECF3C90293E0FB69695D763DAA3AEDA5535B43DAEEDF6E9528E84CEE0EC000C3C8495C1F9C89F6218AF4C23765261CD5ADD0787351992A01E5BB8F2A015807AE7A6BB92A08"）。
* **操作:** `bignum.MultiplyByPowerOfTen(5)`
* **预期输出 (buffer 中的字符串):** "5E13A4863ADEE3E5C9FE8D0A73423D695D62D8450CED15A8C9F368952C6DC3F0EE7D82F3D1EFB7AF38A3B3920D410AFCAD563C8F5F39116E141A3C5C14B358CD73077EA35AAD59F6E24AD98F10D5555ABBFBF33AC361EAF429FD5FBE9417DA9EF2F2956011F9F93646AA38048A681D984ED88127073443247CCC167CB354A32206EF5A733E73CF82D795A1AD598493211A6D613C39515E0E0F6304DCD9C810F3518C7F6A7CB6C81E99E02FCC65E8FDB7B7AE97306CC16A8631CE0A2AEF6568276BE4C176964A73C153FDE018E34CB4C2F40"

**DivideModuloIntBignum 测试:**

* **假设输入:** `bignum` 初始化为 10， `other` 初始化为 2。
* **操作:** `bignum.DivideModuloIntBignum(other)`
* **预期返回值:** 5 (整数商)
* **预期 `bignum` 的值 (buffer 中的字符串):** "0" (余数)

这些测试用例通过具体的输入和预期的输出来验证 `Bignum` 类在各种算术和比较操作中的正确性。

Prompt: 
```
这是目录为v8/test/unittests/base/bignum-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/base/bignum-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
 strcmp("1815699B31E30B3CDFBE17D185F44910BBBF313896C3DC95B4B9314D19B5B32"
             "F57AD71655476B630F3E02DF855502394A74115A5BA2B480BCBCD5F52F6F69D"
             "E6C5622CB5152A54788BD9D14B896DE8CB73B53C3800DDACC9C51E0C38FAE76"
             "2F9964232872F9C2738E7150C4AE3F1B18F70583172706FAEE26DC5A78C77A2"
             "FAA874769E52C01DA5C3499F233ECF3C90293E0FB69695D763DAA3AEDA5535B"
             "43DAEEDF6E9528E84CEE0EC000C3C8495C1F9C89F6218AF4C23765261CD5ADD"
             "0787351992A01E5BB8F2A015807AE7A6BB92A08",
             buffer));

  bignum.AssignBignum(bignum2);
  bignum.MultiplyByPowerOfTen(5);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("5E13A4863ADEE3E5C9FE8D0A73423D695D62D8450CED15A8C9F368952C6DC3"
                "F0EE7D82F3D1EFB7AF38A3B3920D410AFCAD563C8F5F39116E141A3C5C14B3"
                "58CD73077EA35AAD59F6E24AD98F10D5555ABBFBF33AC361EAF429FD5FBE94"
                "17DA9EF2F2956011F9F93646AA38048A681D984ED88127073443247CCC167C"
                "B354A32206EF5A733E73CF82D795A1AD598493211A6D613C39515E0E0F6304"
                "DCD9C810F3518C7F6A7CB6C81E99E02FCC65E8FDB7B7AE97306CC16A8631CE"
                "0A2AEF6568276BE4C176964A73C153FDE018E34CB4C2F40",
                buffer));

  bignum.AssignBignum(bignum2);
  bignum.MultiplyByPowerOfTen(10);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("8F8CB8EB51945A7E815809F6121EF2F4E61EF3405CD9432CAD2709749EEAFD"
                "1B81E843F14A3667A7BDCCC9E0BB795F63CDFDB62844AC7438976C885A0116"
                "29607DA54F9C023CC366570B7637ED0F855D931752038A614922D0923E382C"
                "B8E5F6C975672DB76E0DE471937BB9EDB11E28874F1C122D5E1EF38CECE9D0"
                "0723056BCBD4F964192B76830634B1D322B7EB0062F3267E84F5C824343A77"
                "4B7DCEE6DD464F01EBDC8C671BB18BB4EF4300A42474A6C77243F2A12B03BF"
                "0443C38A1C0D2701EDB393135AE0DEC94211F9D4EB51F990800",
                buffer));

  bignum.AssignBignum(bignum2);
  bignum.MultiplyByPowerOfTen(50);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("107A8BE345E24407372FC1DE442CBA696BC23C4FFD5B4BDFD9E5C39559815"
                "86628CF8472D2D589F2FC2BAD6E0816EC72CBF85CCA663D8A1EC6C51076D8"
                "2D247E6C26811B7EC4D4300FB1F91028DCB7B2C4E7A60C151161AA7E65E79"
                "B40917B12B2B5FBE7745984D4E8EFA31F9AE6062427B068B144A9CB155873"
                "E7C0C9F0115E5AC72DC5A73C4796DB970BF9205AB8C77A6996EB1B417F9D1"
                "6232431E6313C392203601B9C22CC10DDA88DCC6D282605F8DB67044F2DFD"
                "3695E7BA63877AE16701536AE6567C794D0BFE338DFBB42D924CF964BD2C0"
                "F586E03A2FCD35A408000000000000",
                buffer));

  bignum.AssignBignum(bignum2);
  bignum.MultiplyByPowerOfTen(100);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("46784A90ACD0ED3E7759CC585FB32D36EB6034A6F78D92604E3BAA5ED3D8B"
                "6E60E854439BE448897FB4B7EA5A3D873AA0FCB3CFFD80D0530880E45F511"
                "722A50CE7E058B5A6F5464DB7500E34984EE3202A9441F44FA1554C0CEA96"
                "B438A36F25E7C9D56D71AE2CD313EC37534DA299AC0854FC48591A7CF3171"
                "31265AA4AE62DE32344CE7BEEEF894AE686A2DAAFE5D6D9A10971FFD9C064"
                "5079B209E1048F58B5192D41D84336AC4C8C489EEF00939CFC9D55C122036"
                "01B9C22CC10DDA88DCC6D282605F8DB67044F2DFD3695E7BA3F67B96D3A32"
                "E11FB5561B68744C4035B0800DC166D49D98E3FD1D5BB2000000000000000"
                "0000000000",
                buffer));

  bignum.AssignBignum(bignum2);
  bignum.MultiplyByPowerOfTen(200);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("508BD351221DF139D72D88CDC0416845A53EE2D0E6B98352509A9AC312F8C"
                "6CB1A144889416201E0B6CE66EA3EBE259B5FD79ECFC1FD77963CE516CC7E"
                "2FE73D4B5B710C19F6BCB092C7A2FD76286543B8DBD2C596DFF2C896720BA"
                "DFF7BC9C366ACEA3A880AEC287C5E6207DF2739B5326FC19D773BD830B109"
                "ED36C7086544BF8FDB9D4B73719C2B5BC2F571A5937EC46876CD428281F6B"
                "F287E1E07F25C1B1D46BC37324FF657A8B2E0071DB83B86123CA34004F406"
                "001082D7945E90C6E8C9A9FEC2B44BE0DDA46E9F52B152E4D1336D2FCFBC9"
                "96E30CA0082256737365158FE36482AA7EB9DAF2AB128F10E7551A3CD5BE6"
                "0A922F3A7D5EED38B634A7EC95BCF7021BA6820A292000000000000000000"
                "00000000000000000000000000000000",
                buffer));

  bignum.AssignBignum(bignum2);
  bignum.MultiplyByPowerOfTen(500);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(
      0, strcmp("7845F900E475B5086885BAAAE67C8E85185ACFE4633727F82A4B06B5582AC"
                "BE933C53357DA0C98C20C5AC900C4D76A97247DF52B79F48F9E35840FB715"
                "D392CE303E22622B0CF82D9471B398457DD3196F639CEE8BBD2C146873841"
                "F0699E6C41F04FC7A54B48CEB995BEB6F50FE81DE9D87A8D7F849CC523553"
                "7B7BBBC1C7CAAFF6E9650BE03B308C6D31012AEF9580F70D3EE2083ADE126"
                "8940FA7D6308E239775DFD2F8C97FF7EBD525DAFA6512216F7047A62A93DC"
                "38A0165BDC67E250DCC96A0181DE935A70B38704DC71819F02FC5261FF7E1"
                "E5F11907678B0A3E519FF4C10A867B0C26CE02BE6960BA8621A87303C101C"
                "3F88798BB9F7739655946F8B5744E6B1EAF10B0C5621330F0079209033C69"
                "20DE2E2C8D324F0624463735D482BF291926C22A910F5B80FA25170B6B57D"
                "8D5928C7BCA3FE87461275F69BD5A1B83181DAAF43E05FC3C72C4E93111B6"
                "6205EBF49B28FEDFB7E7526CBDA658A332000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000",
                buffer));
}

TEST_F(BignumTest, DivideModuloIntBignum) {
  char buffer[kBufferSize];
  Bignum bignum;
  Bignum other;
  Bignum third;

  bignum.AssignUInt16(10);
  other.AssignUInt16(2);
  EXPECT_EQ(5, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("0", buffer));

  bignum.AssignUInt16(10);
  bignum.ShiftLeft(500);
  other.AssignUInt16(2);
  other.ShiftLeft(500);
  EXPECT_EQ(5, bignum.DivideModuloIntBignum(other));
  EXPECT_EQ(0, strcmp("0", buffer));

  bignum.AssignUInt16(11);
  other.AssignUInt16(2);
  EXPECT_EQ(5, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignUInt16(10);
  bignum.ShiftLeft(500);
  other.AssignUInt16(1);
  bignum.AddBignum(other);
  other.AssignUInt16(2);
  other.ShiftLeft(500);
  EXPECT_EQ(5, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignUInt16(10);
  bignum.ShiftLeft(500);
  other.AssignBignum(bignum);
  bignum.MultiplyByUInt32(0x1234);
  third.AssignUInt16(0xFFF);
  bignum.AddBignum(third);
  EXPECT_EQ(0x1234, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFF", buffer));

  bignum.AssignUInt16(10);
  AssignHexString(&other, "1234567890");
  EXPECT_EQ(0, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A", buffer));

  AssignHexString(&bignum, "12345678");
  AssignHexString(&other, "3789012");
  EXPECT_EQ(5, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("D9861E", buffer));

  AssignHexString(&bignum, "70000001");
  AssignHexString(&other, "1FFFFFFF");
  EXPECT_EQ(3, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000004", buffer));

  AssignHexString(&bignum, "28000000");
  AssignHexString(&other, "12A05F20");
  EXPECT_EQ(2, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2BF41C0", buffer));

  bignum.AssignUInt16(10);
  bignum.ShiftLeft(500);
  other.AssignBignum(bignum);
  bignum.MultiplyByUInt32(0x1234);
  third.AssignUInt16(0xFFF);
  other.SubtractBignum(third);
  EXPECT_EQ(0x1234, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1232DCC", buffer));
  EXPECT_EQ(0, bignum.DivideModuloIntBignum(other));
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1232DCC", buffer));
}

TEST_F(BignumTest, Compare) {
  Bignum bignum1;
  Bignum bignum2;
  bignum1.AssignUInt16(1);
  bignum2.AssignUInt16(1);
  EXPECT_EQ(0, Bignum::Compare(bignum1, bignum2));
  EXPECT_TRUE(Bignum::Equal(bignum1, bignum2));
  EXPECT_TRUE(Bignum::LessEqual(bignum1, bignum2));
  EXPECT_TRUE(!Bignum::Less(bignum1, bignum2));

  bignum1.AssignUInt16(0);
  bignum2.AssignUInt16(1);
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));
  EXPECT_TRUE(!Bignum::Equal(bignum1, bignum2));
  EXPECT_TRUE(!Bignum::Equal(bignum2, bignum1));
  EXPECT_TRUE(Bignum::LessEqual(bignum1, bignum2));
  EXPECT_TRUE(!Bignum::LessEqual(bignum2, bignum1));
  EXPECT_TRUE(Bignum::Less(bignum1, bignum2));
  EXPECT_TRUE(!Bignum::Less(bignum2, bignum1));

  AssignHexString(&bignum1, "1234567890ABCDEF12345");
  AssignHexString(&bignum2, "1234567890ABCDEF12345");
  EXPECT_EQ(0, Bignum::Compare(bignum1, bignum2));

  AssignHexString(&bignum1, "1234567890ABCDEF12345");
  AssignHexString(&bignum2, "1234567890ABCDEF12346");
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));

  AssignHexString(&bignum1, "1234567890ABCDEF12345");
  bignum1.ShiftLeft(500);
  AssignHexString(&bignum2, "1234567890ABCDEF12345");
  bignum2.ShiftLeft(500);
  EXPECT_EQ(0, Bignum::Compare(bignum1, bignum2));

  AssignHexString(&bignum1, "1234567890ABCDEF12345");
  bignum1.ShiftLeft(500);
  AssignHexString(&bignum2, "1234567890ABCDEF12346");
  bignum2.ShiftLeft(500);
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));

  bignum1.AssignUInt16(1);
  bignum1.ShiftLeft(64);
  AssignHexString(&bignum2, "10000000000000000");
  EXPECT_EQ(0, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(0, Bignum::Compare(bignum2, bignum1));

  bignum1.AssignUInt16(1);
  bignum1.ShiftLeft(64);
  AssignHexString(&bignum2, "10000000000000001");
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));

  bignum1.AssignUInt16(1);
  bignum1.ShiftLeft(96);
  AssignHexString(&bignum2, "10000000000000001");
  bignum2.ShiftLeft(32);
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));

  AssignHexString(&bignum1, "FFFFFFFFFFFFFFFF");
  bignum2.AssignUInt16(1);
  bignum2.ShiftLeft(64);
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));

  AssignHexString(&bignum1, "FFFFFFFFFFFFFFFF");
  bignum1.ShiftLeft(32);
  bignum2.AssignUInt16(1);
  bignum2.ShiftLeft(96);
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));

  AssignHexString(&bignum1, "FFFFFFFFFFFFFFFF");
  bignum1.ShiftLeft(32);
  bignum2.AssignUInt16(1);
  bignum2.ShiftLeft(95);
  EXPECT_EQ(+1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(-1, Bignum::Compare(bignum2, bignum1));

  AssignHexString(&bignum1, "FFFFFFFFFFFFFFFF");
  bignum1.ShiftLeft(32);
  bignum2.AssignUInt16(1);
  bignum2.ShiftLeft(100);
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));

  AssignHexString(&bignum1, "100000000000000");
  bignum2.AssignUInt16(1);
  bignum2.ShiftLeft(14 * 4);
  EXPECT_EQ(0, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(0, Bignum::Compare(bignum2, bignum1));

  AssignHexString(&bignum1, "100000000000001");
  bignum2.AssignUInt16(1);
  bignum2.ShiftLeft(14 * 4);
  EXPECT_EQ(+1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(-1, Bignum::Compare(bignum2, bignum1));

  AssignHexString(&bignum1, "200000000000000");
  bignum2.AssignUInt16(3);
  bignum2.ShiftLeft(14 * 4);
  EXPECT_EQ(-1, Bignum::Compare(bignum1, bignum2));
  EXPECT_EQ(+1, Bignum::Compare(bignum2, bignum1));
}

TEST_F(BignumTest, PlusCompare) {
  Bignum a;
  Bignum b;
  Bignum c;
  a.AssignUInt16(1);
  b.AssignUInt16(0);
  c.AssignUInt16(1);
  EXPECT_EQ(0, Bignum::PlusCompare(a, b, c));
  EXPECT_TRUE(Bignum::PlusEqual(a, b, c));
  EXPECT_TRUE(Bignum::PlusLessEqual(a, b, c));
  EXPECT_TRUE(!Bignum::PlusLess(a, b, c));

  a.AssignUInt16(0);
  b.AssignUInt16(0);
  c.AssignUInt16(1);
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));
  EXPECT_EQ(+1, Bignum::PlusCompare(c, b, a));
  EXPECT_TRUE(!Bignum::PlusEqual(a, b, c));
  EXPECT_TRUE(!Bignum::PlusEqual(c, b, a));
  EXPECT_TRUE(Bignum::PlusLessEqual(a, b, c));
  EXPECT_TRUE(!Bignum::PlusLessEqual(c, b, a));
  EXPECT_TRUE(Bignum::PlusLess(a, b, c));
  EXPECT_TRUE(!Bignum::PlusLess(c, b, a));

  AssignHexString(&a, "1234567890ABCDEF12345");
  b.AssignUInt16(1);
  AssignHexString(&c, "1234567890ABCDEF12345");
  EXPECT_EQ(+1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890ABCDEF12344");
  b.AssignUInt16(1);
  AssignHexString(&c, "1234567890ABCDEF12345");
  EXPECT_EQ(0, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4);
  AssignHexString(&b, "ABCDEF12345");
  AssignHexString(&c, "1234567890ABCDEF12345");
  EXPECT_EQ(0, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4);
  AssignHexString(&b, "ABCDEF12344");
  AssignHexString(&c, "1234567890ABCDEF12345");
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4);
  AssignHexString(&b, "ABCDEF12346");
  AssignHexString(&c, "1234567890ABCDEF12345");
  EXPECT_EQ(1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567891");
  a.ShiftLeft(11 * 4);
  AssignHexString(&b, "ABCDEF12345");
  AssignHexString(&c, "1234567890ABCDEF12345");
  EXPECT_EQ(1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567889");
  a.ShiftLeft(11 * 4);
  AssignHexString(&b, "ABCDEF12345");
  AssignHexString(&c, "1234567890ABCDEF12345");
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF12345");
  c.ShiftLeft(32);
  EXPECT_EQ(0, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12344");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF12345");
  c.ShiftLeft(32);
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12346");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF12345");
  c.ShiftLeft(32);
  EXPECT_EQ(1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567891");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF12345");
  c.ShiftLeft(32);
  EXPECT_EQ(1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567889");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF12345");
  c.ShiftLeft(32);
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF1234500000000");
  EXPECT_EQ(0, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12344");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF1234500000000");
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12346");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF1234500000000");
  EXPECT_EQ(1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567891");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF1234500000000");
  EXPECT_EQ(1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567889");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  b.ShiftLeft(32);
  AssignHexString(&c, "1234567890ABCDEF1234500000000");
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  AssignHexString(&c, "123456789000000000ABCDEF12345");
  EXPECT_EQ(0, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12346");
  AssignHexString(&c, "123456789000000000ABCDEF12345");
  EXPECT_EQ(1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12344");
  AssignHexString(&c, "123456789000000000ABCDEF12345");
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  b.ShiftLeft(16);
  AssignHexString(&c, "12345678900000ABCDEF123450000");
  EXPECT_EQ(0, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12344");
  b.ShiftLeft(16);
  AssignHexString(&c, "12345678900000ABCDEF123450000");
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12345");
  b.ShiftLeft(16);
  AssignHexString(&c, "12345678900000ABCDEF123450001");
  EXPECT_EQ(-1, Bignum::PlusCompare(a, b, c));

  AssignHexString(&a, "1234567890");
  a.ShiftLeft(11 * 4 + 32);
  AssignHexString(&b, "ABCDEF12346");
  b.ShiftLeft(16);
  AssignHexString(&c, "12345678900000ABCDEF123450000");
  EXPECT_EQ(+1, Bignum::PlusCompare(a, b, c));
}

TEST_F(BignumTest, Square) {
  Bignum bignum;
  char buffer[kBufferSize];

  bignum.AssignUInt16(1);
  bignum.Square();
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignUInt16(2);
  bignum.Square();
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("4", buffer));

  bignum.AssignUInt16(10);
  bignum.Square();
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("64", buffer));

  AssignHexString(&bignum, "FFFFFFF");
  bignum.Square();
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFE0000001", buffer));

  AssignHexString(&bignum, "FFFFFFFFFFFFFF");
  bignum.Square();
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("FFFFFFFFFFFFFE00000000000001", buffer));
}

TEST_F(BignumTest, AssignPowerUInt16) {
  Bignum bignum;
  char buffer[kBufferSize];

  bignum.AssignPowerUInt16(1, 0);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignPowerUInt16(1, 1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignPowerUInt16(1, 2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignPowerUInt16(2, 0);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignPowerUInt16(2, 1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2", buffer));

  bignum.AssignPowerUInt16(2, 2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("4", buffer));

  bignum.AssignPowerUInt16(16, 1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10", buffer));

  bignum.AssignPowerUInt16(16, 2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100", buffer));

  bignum.AssignPowerUInt16(16, 5);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100000", buffer));

  bignum.AssignPowerUInt16(16, 8);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("100000000", buffer));

  bignum.AssignPowerUInt16(16, 16);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000", buffer));

  bignum.AssignPowerUInt16(16, 30);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1000000000000000000000000000000", buffer));

  bignum.AssignPowerUInt16(10, 0);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignPowerUInt16(10, 1);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("A", buffer));

  bignum.AssignPowerUInt16(10, 2);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("64", buffer));

  bignum.AssignPowerUInt16(10, 5);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("186A0", buffer));

  bignum.AssignPowerUInt16(10, 8);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("5F5E100", buffer));

  bignum.AssignPowerUInt16(10, 16);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("2386F26FC10000", buffer));

  bignum.AssignPowerUInt16(10, 30);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("C9F2C9CD04674EDEA40000000", buffer));

  bignum.AssignPowerUInt16(10, 31);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("7E37BE2022C0914B2680000000", buffer));

  bignum.AssignPowerUInt16(2, 0);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignPowerUInt16(2, 100);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("10000000000000000000000000", buffer));

  bignum.AssignPowerUInt16(17, 0);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1", buffer));

  bignum.AssignPowerUInt16(17, 99);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0, strcmp("1942BB9853FAD924A3D4DD92B89B940E0207BEF05DB9C26BC1B757"
                      "80BE0C5A2C2990E02A681224F34ED68558CE4C6E33760931",
                      buffer));

  bignum.AssignPowerUInt16(0xFFFF, 99);
  EXPECT_TRUE(bignum.ToHexString(buffer, kBufferSize));
  EXPECT_EQ(0,
            strcmp("FF9D12F09B886C54E77E7439C7D2DED2D34F669654C0C2B6B8C288250"
                   "5A2211D0E3DC9A61831349EAE674B11D56E3049D7BD79DAAD6C9FA2BA"
                   "528E3A794299F2EE9146A324DAFE3E88967A0358233B543E233E575B9"
                   "DD4E3AA7942146426C328FF55BFD5C45E0901B1629260AF9AE2F310C5"
                   "50959FAF305C30116D537D80CF6EBDBC15C5694062AF1AC3D956D0A41"
                   "B7E1B79FF11E21D83387A1CE1F5882B31E4B5D8DE415BDBE6854466DF"
                   "343362267A7E8833119D31D02E18DB5B0E8F6A64B0ED0D0062FFFF",
                   buffer));
}

}  // namespace test_bignum
}  // namespace base
}  // namespace v8

"""


```