Response:
The user has provided the second part of a Go source code snippet from `go/src/strconv/eisel_lemire.go`. The first part was analyzed in a previous interaction. The task is to summarize the functionality of this second part and, in conjunction with the first part, describe the overall functionality of the `eisel_lemire.go` file.

**Breakdown of the request:**

1. **List the functions of this part:**  This involves identifying what the code in this second part does.
2. **Infer the overall Go functionality:** Based on both parts, determine what high-level Go feature this file implements.
3. **Provide a Go code example:** Illustrate the inferred functionality with a practical Go code snippet, including input and output.
4. **Handle code reasoning (if applicable):**  Since the code primarily consists of data, the reasoning will involve understanding the structure and purpose of that data.
5. **Describe command-line argument handling (if applicable):** This seems unlikely for this specific file, which appears to be a data-driven implementation.
6. **Point out common mistakes (if applicable):**  Consider potential errors users might make when interacting with the functionality implemented by this file.
7. **Summarize the functionality of *this* part:** A specific summary focusing on the data presented in this second snippet.
8. **Summarize the functionality of the *entire* file:**  A combined summary of both parts.

**Analysis of the second part of the code:**

This part consists of a large constant array named `powersOf10`. Each element in the array is a struct containing two `uint64` values. Looking at the comments preceding each struct literal (e.g., `// 1e163`, `// 1e164`), it's clear that these structs represent powers of 10. The two `uint64` values likely represent the high and low parts of a 128-bit representation of these large powers of 10.

**Connecting to the first part:**

The first part likely contained the initial powers of 10, starting from 1 up to a certain point. This second part continues the sequence of powers of 10 for even larger exponents.

**Inferring overall functionality:**

Given that the file is named `eisel_lemire.go`, which refers to the Eisel-Lemire algorithm, and the content is a table of pre-computed powers of 10, it's highly probable that this file is used for efficient conversion between floating-point numbers and their string representations. The Eisel-Lemire algorithm is known for its speed and accuracy in this domain. The pre-computed powers of 10 are a crucial component for scaling and rounding during the conversion process.

**Plan for generating the response:**

1. **Summarize the functionality of the second part:** Focus on the `powersOf10` array and its purpose of storing high-precision powers of 10 for large exponents.
2. **Summarize the functionality of the entire file:**  Combine the analysis of both parts, emphasizing the role of the `powersOf10` array in the Eisel-Lemire algorithm for string conversion of floating-point numbers.
3. **Provide a Go code example:** Show a simple example of using `strconv.FormatFloat` and `strconv.ParseFloat`, highlighting the implicit use of the `eisel_lemire.go` logic. Include example input and output.
4. **Address other points:** Briefly mention the data-driven nature of the file, the lack of command-line arguments, and potential mistakes related to understanding the limitations of floating-point representation.
这是`go/src/strconv/eisel_lemire.go`文件的第二部分，与第一部分结合起来，我们可以更全面地了解它的功能。

**第二部分的功能：**

这部分代码定义了一个名为 `powersOf10` 的常量切片，其中包含了更多更大的 10 的幂的 128 位表示。具体来说，它延续了第一部分中 `powersOf10` 的定义，存储了从 10<sup>163</sup> 到 10<sup>347</sup> 的 10 的幂。

每个元素都是一个结构体，包含两个 `uint64` 类型的字段。这两个 `uint64` 值组合起来表示一个 128 位的整数，用于精确存储非常大的 10 的幂。 注释 `// 1e163` 等标明了对应的 10 的幂。

**结合第一部分，整个文件的功能归纳：**

`go/src/strconv/eisel_lemire.go` 文件的主要功能是提供一个高效且精确的方法来将浮点数转换为字符串，以及将字符串解析为浮点数。 它实现了 **Eisel-Lemire 算法** 的一部分，该算法专门用于处理浮点数和十进制字符串之间的转换。

该文件通过预先计算并存储一系列精确的 10 的幂（以 128 位整数形式存储在 `powersOf10` 切片中），来加速和保证转换的精度。 这些预先计算的值在算法中被用来进行快速的乘法和除法运算，避免了直接计算大数带来的精度损失和性能问题。

**Go 代码举例说明：**

这个文件本身不包含可直接调用的函数，它更多的是作为 `strconv` 包内部实现的一部分被使用。  `strconv` 包提供了 `FormatFloat` 和 `ParseFloat` 等函数，这些函数在底层可能会利用 `eisel_lemire.go` 中定义的 `powersOf10`。

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	// 将浮点数转换为字符串
	floatNum := 1.2345e+200
	str := strconv.FormatFloat(floatNum, 'G', 10, 64) // 使用 'G' 格式，10 位精度，64 位浮点数
	fmt.Println("浮点数转换为字符串:", str) // 输出类似：浮点数转换为字符串: 1.2345e+200

	// 将字符串解析为浮点数
	parsedFloat, err := strconv.ParseFloat("1.2345e+200", 64)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}
	fmt.Println("字符串解析为浮点数:", parsedFloat) // 输出类似：字符串解析为浮点数: 1.2345e+200
}
```

**假设的输入与输出：**

在上面的例子中：

* **`strconv.FormatFloat` 的输入:** `floatNum = 1.2345e+200`
* **`strconv.FormatFloat` 的输出:**  `"1.2345e+200"` (具体的输出格式可能略有不同，取决于精度和其他参数)

* **`strconv.ParseFloat` 的输入:** `"1.2345e+200"`
* **`strconv.ParseFloat` 的输出:** `1.2345e+200` (float64 类型)

**代码推理：**

`eisel_lemire.go` 中 `powersOf10` 存储的 10 的幂被 `strconv` 包内部的浮点数格式化和解析逻辑使用。 当需要将一个非常大的或非常小的浮点数转换为字符串时，算法会查找最接近的 10 的幂，并利用预先计算的 128 位值进行精确的缩放和计算，以避免浮点数运算的精度损失。  例如，当格式化 `1.2345e+200` 时，算法可能会用到 `powersOf10` 中接近 10<sup>200</sup> 的值。

**命令行参数的处理：**

`eisel_lemire.go` 文件本身不处理命令行参数。 它的作用是提供数据支持，被 `strconv` 包的函数在内部使用。 `strconv` 包的函数本身也不会直接接受命令行参数。

**使用者易犯错的点：**

虽然使用者不会直接操作 `eisel_lemire.go` 中的代码，但理解浮点数的局限性以及 `strconv` 包的功能仍然很重要。

* **误解浮点数的精度：** 用户可能会认为浮点数能精确表示所有的十进制数，但实际上浮点数是二进制表示，某些十进制数无法精确表示。 `eisel_lemire.go` 的目标是提供尽可能精确的 *转换*，而不是改变浮点数本身的表示限制。

  **例子：**

  ```go
  package main

  import (
  	"fmt"
  	"strconv"
  )

  func main() {
  	f := 0.1 + 0.2
  	fmt.Println(f) // 输出类似：0.30000000000000004，而不是精确的 0.3

  	str := strconv.FormatFloat(f, 'G', 17, 64) // 尽可能高的精度
  	fmt.Println(str) // 输出类似：0.30000000000000004
  }
  ```
  在这个例子中，即使 `eisel_lemire.go` 提供了精确的转换能力，但由于 `0.1` 和 `0.2` 本身在二进制浮点数中就不能被精确表示，最终的结果仍然会有微小的误差。

**归纳一下它的功能（针对第二部分）：**

第二部分的主要功能是扩展了 `powersOf10` 常量切片，提供了从 10<sup>163</sup> 到 10<sup>347</sup> 的更大范围的 10 的幂的精确 128 位表示。 这使得 `strconv` 包在处理非常大的浮点数时能够保持较高的精度。

### 提示词
```
这是路径为go/src/strconv/eisel_lemire.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
2D8AE258FC8, 0xB1D219647AE6B31C}, // 1e163
	{0x6FCA5F8ED9AEF3BB, 0xDE469FBD99A05FE3}, // 1e164
	{0x25DE7BB9480D5854, 0x8AEC23D680043BEE}, // 1e165
	{0xAF561AA79A10AE6A, 0xADA72CCC20054AE9}, // 1e166
	{0x1B2BA1518094DA04, 0xD910F7FF28069DA4}, // 1e167
	{0x90FB44D2F05D0842, 0x87AA9AFF79042286}, // 1e168
	{0x353A1607AC744A53, 0xA99541BF57452B28}, // 1e169
	{0x42889B8997915CE8, 0xD3FA922F2D1675F2}, // 1e170
	{0x69956135FEBADA11, 0x847C9B5D7C2E09B7}, // 1e171
	{0x43FAB9837E699095, 0xA59BC234DB398C25}, // 1e172
	{0x94F967E45E03F4BB, 0xCF02B2C21207EF2E}, // 1e173
	{0x1D1BE0EEBAC278F5, 0x8161AFB94B44F57D}, // 1e174
	{0x6462D92A69731732, 0xA1BA1BA79E1632DC}, // 1e175
	{0x7D7B8F7503CFDCFE, 0xCA28A291859BBF93}, // 1e176
	{0x5CDA735244C3D43E, 0xFCB2CB35E702AF78}, // 1e177
	{0x3A0888136AFA64A7, 0x9DEFBF01B061ADAB}, // 1e178
	{0x088AAA1845B8FDD0, 0xC56BAEC21C7A1916}, // 1e179
	{0x8AAD549E57273D45, 0xF6C69A72A3989F5B}, // 1e180
	{0x36AC54E2F678864B, 0x9A3C2087A63F6399}, // 1e181
	{0x84576A1BB416A7DD, 0xC0CB28A98FCF3C7F}, // 1e182
	{0x656D44A2A11C51D5, 0xF0FDF2D3F3C30B9F}, // 1e183
	{0x9F644AE5A4B1B325, 0x969EB7C47859E743}, // 1e184
	{0x873D5D9F0DDE1FEE, 0xBC4665B596706114}, // 1e185
	{0xA90CB506D155A7EA, 0xEB57FF22FC0C7959}, // 1e186
	{0x09A7F12442D588F2, 0x9316FF75DD87CBD8}, // 1e187
	{0x0C11ED6D538AEB2F, 0xB7DCBF5354E9BECE}, // 1e188
	{0x8F1668C8A86DA5FA, 0xE5D3EF282A242E81}, // 1e189
	{0xF96E017D694487BC, 0x8FA475791A569D10}, // 1e190
	{0x37C981DCC395A9AC, 0xB38D92D760EC4455}, // 1e191
	{0x85BBE253F47B1417, 0xE070F78D3927556A}, // 1e192
	{0x93956D7478CCEC8E, 0x8C469AB843B89562}, // 1e193
	{0x387AC8D1970027B2, 0xAF58416654A6BABB}, // 1e194
	{0x06997B05FCC0319E, 0xDB2E51BFE9D0696A}, // 1e195
	{0x441FECE3BDF81F03, 0x88FCF317F22241E2}, // 1e196
	{0xD527E81CAD7626C3, 0xAB3C2FDDEEAAD25A}, // 1e197
	{0x8A71E223D8D3B074, 0xD60B3BD56A5586F1}, // 1e198
	{0xF6872D5667844E49, 0x85C7056562757456}, // 1e199
	{0xB428F8AC016561DB, 0xA738C6BEBB12D16C}, // 1e200
	{0xE13336D701BEBA52, 0xD106F86E69D785C7}, // 1e201
	{0xECC0024661173473, 0x82A45B450226B39C}, // 1e202
	{0x27F002D7F95D0190, 0xA34D721642B06084}, // 1e203
	{0x31EC038DF7B441F4, 0xCC20CE9BD35C78A5}, // 1e204
	{0x7E67047175A15271, 0xFF290242C83396CE}, // 1e205
	{0x0F0062C6E984D386, 0x9F79A169BD203E41}, // 1e206
	{0x52C07B78A3E60868, 0xC75809C42C684DD1}, // 1e207
	{0xA7709A56CCDF8A82, 0xF92E0C3537826145}, // 1e208
	{0x88A66076400BB691, 0x9BBCC7A142B17CCB}, // 1e209
	{0x6ACFF893D00EA435, 0xC2ABF989935DDBFE}, // 1e210
	{0x0583F6B8C4124D43, 0xF356F7EBF83552FE}, // 1e211
	{0xC3727A337A8B704A, 0x98165AF37B2153DE}, // 1e212
	{0x744F18C0592E4C5C, 0xBE1BF1B059E9A8D6}, // 1e213
	{0x1162DEF06F79DF73, 0xEDA2EE1C7064130C}, // 1e214
	{0x8ADDCB5645AC2BA8, 0x9485D4D1C63E8BE7}, // 1e215
	{0x6D953E2BD7173692, 0xB9A74A0637CE2EE1}, // 1e216
	{0xC8FA8DB6CCDD0437, 0xE8111C87C5C1BA99}, // 1e217
	{0x1D9C9892400A22A2, 0x910AB1D4DB9914A0}, // 1e218
	{0x2503BEB6D00CAB4B, 0xB54D5E4A127F59C8}, // 1e219
	{0x2E44AE64840FD61D, 0xE2A0B5DC971F303A}, // 1e220
	{0x5CEAECFED289E5D2, 0x8DA471A9DE737E24}, // 1e221
	{0x7425A83E872C5F47, 0xB10D8E1456105DAD}, // 1e222
	{0xD12F124E28F77719, 0xDD50F1996B947518}, // 1e223
	{0x82BD6B70D99AAA6F, 0x8A5296FFE33CC92F}, // 1e224
	{0x636CC64D1001550B, 0xACE73CBFDC0BFB7B}, // 1e225
	{0x3C47F7E05401AA4E, 0xD8210BEFD30EFA5A}, // 1e226
	{0x65ACFAEC34810A71, 0x8714A775E3E95C78}, // 1e227
	{0x7F1839A741A14D0D, 0xA8D9D1535CE3B396}, // 1e228
	{0x1EDE48111209A050, 0xD31045A8341CA07C}, // 1e229
	{0x934AED0AAB460432, 0x83EA2B892091E44D}, // 1e230
	{0xF81DA84D5617853F, 0xA4E4B66B68B65D60}, // 1e231
	{0x36251260AB9D668E, 0xCE1DE40642E3F4B9}, // 1e232
	{0xC1D72B7C6B426019, 0x80D2AE83E9CE78F3}, // 1e233
	{0xB24CF65B8612F81F, 0xA1075A24E4421730}, // 1e234
	{0xDEE033F26797B627, 0xC94930AE1D529CFC}, // 1e235
	{0x169840EF017DA3B1, 0xFB9B7CD9A4A7443C}, // 1e236
	{0x8E1F289560EE864E, 0x9D412E0806E88AA5}, // 1e237
	{0xF1A6F2BAB92A27E2, 0xC491798A08A2AD4E}, // 1e238
	{0xAE10AF696774B1DB, 0xF5B5D7EC8ACB58A2}, // 1e239
	{0xACCA6DA1E0A8EF29, 0x9991A6F3D6BF1765}, // 1e240
	{0x17FD090A58D32AF3, 0xBFF610B0CC6EDD3F}, // 1e241
	{0xDDFC4B4CEF07F5B0, 0xEFF394DCFF8A948E}, // 1e242
	{0x4ABDAF101564F98E, 0x95F83D0A1FB69CD9}, // 1e243
	{0x9D6D1AD41ABE37F1, 0xBB764C4CA7A4440F}, // 1e244
	{0x84C86189216DC5ED, 0xEA53DF5FD18D5513}, // 1e245
	{0x32FD3CF5B4E49BB4, 0x92746B9BE2F8552C}, // 1e246
	{0x3FBC8C33221DC2A1, 0xB7118682DBB66A77}, // 1e247
	{0x0FABAF3FEAA5334A, 0xE4D5E82392A40515}, // 1e248
	{0x29CB4D87F2A7400E, 0x8F05B1163BA6832D}, // 1e249
	{0x743E20E9EF511012, 0xB2C71D5BCA9023F8}, // 1e250
	{0x914DA9246B255416, 0xDF78E4B2BD342CF6}, // 1e251
	{0x1AD089B6C2F7548E, 0x8BAB8EEFB6409C1A}, // 1e252
	{0xA184AC2473B529B1, 0xAE9672ABA3D0C320}, // 1e253
	{0xC9E5D72D90A2741E, 0xDA3C0F568CC4F3E8}, // 1e254
	{0x7E2FA67C7A658892, 0x8865899617FB1871}, // 1e255
	{0xDDBB901B98FEEAB7, 0xAA7EEBFB9DF9DE8D}, // 1e256
	{0x552A74227F3EA565, 0xD51EA6FA85785631}, // 1e257
	{0xD53A88958F87275F, 0x8533285C936B35DE}, // 1e258
	{0x8A892ABAF368F137, 0xA67FF273B8460356}, // 1e259
	{0x2D2B7569B0432D85, 0xD01FEF10A657842C}, // 1e260
	{0x9C3B29620E29FC73, 0x8213F56A67F6B29B}, // 1e261
	{0x8349F3BA91B47B8F, 0xA298F2C501F45F42}, // 1e262
	{0x241C70A936219A73, 0xCB3F2F7642717713}, // 1e263
	{0xED238CD383AA0110, 0xFE0EFB53D30DD4D7}, // 1e264
	{0xF4363804324A40AA, 0x9EC95D1463E8A506}, // 1e265
	{0xB143C6053EDCD0D5, 0xC67BB4597CE2CE48}, // 1e266
	{0xDD94B7868E94050A, 0xF81AA16FDC1B81DA}, // 1e267
	{0xCA7CF2B4191C8326, 0x9B10A4E5E9913128}, // 1e268
	{0xFD1C2F611F63A3F0, 0xC1D4CE1F63F57D72}, // 1e269
	{0xBC633B39673C8CEC, 0xF24A01A73CF2DCCF}, // 1e270
	{0xD5BE0503E085D813, 0x976E41088617CA01}, // 1e271
	{0x4B2D8644D8A74E18, 0xBD49D14AA79DBC82}, // 1e272
	{0xDDF8E7D60ED1219E, 0xEC9C459D51852BA2}, // 1e273
	{0xCABB90E5C942B503, 0x93E1AB8252F33B45}, // 1e274
	{0x3D6A751F3B936243, 0xB8DA1662E7B00A17}, // 1e275
	{0x0CC512670A783AD4, 0xE7109BFBA19C0C9D}, // 1e276
	{0x27FB2B80668B24C5, 0x906A617D450187E2}, // 1e277
	{0xB1F9F660802DEDF6, 0xB484F9DC9641E9DA}, // 1e278
	{0x5E7873F8A0396973, 0xE1A63853BBD26451}, // 1e279
	{0xDB0B487B6423E1E8, 0x8D07E33455637EB2}, // 1e280
	{0x91CE1A9A3D2CDA62, 0xB049DC016ABC5E5F}, // 1e281
	{0x7641A140CC7810FB, 0xDC5C5301C56B75F7}, // 1e282
	{0xA9E904C87FCB0A9D, 0x89B9B3E11B6329BA}, // 1e283
	{0x546345FA9FBDCD44, 0xAC2820D9623BF429}, // 1e284
	{0xA97C177947AD4095, 0xD732290FBACAF133}, // 1e285
	{0x49ED8EABCCCC485D, 0x867F59A9D4BED6C0}, // 1e286
	{0x5C68F256BFFF5A74, 0xA81F301449EE8C70}, // 1e287
	{0x73832EEC6FFF3111, 0xD226FC195C6A2F8C}, // 1e288
	{0xC831FD53C5FF7EAB, 0x83585D8FD9C25DB7}, // 1e289
	{0xBA3E7CA8B77F5E55, 0xA42E74F3D032F525}, // 1e290
	{0x28CE1BD2E55F35EB, 0xCD3A1230C43FB26F}, // 1e291
	{0x7980D163CF5B81B3, 0x80444B5E7AA7CF85}, // 1e292
	{0xD7E105BCC332621F, 0xA0555E361951C366}, // 1e293
	{0x8DD9472BF3FEFAA7, 0xC86AB5C39FA63440}, // 1e294
	{0xB14F98F6F0FEB951, 0xFA856334878FC150}, // 1e295
	{0x6ED1BF9A569F33D3, 0x9C935E00D4B9D8D2}, // 1e296
	{0x0A862F80EC4700C8, 0xC3B8358109E84F07}, // 1e297
	{0xCD27BB612758C0FA, 0xF4A642E14C6262C8}, // 1e298
	{0x8038D51CB897789C, 0x98E7E9CCCFBD7DBD}, // 1e299
	{0xE0470A63E6BD56C3, 0xBF21E44003ACDD2C}, // 1e300
	{0x1858CCFCE06CAC74, 0xEEEA5D5004981478}, // 1e301
	{0x0F37801E0C43EBC8, 0x95527A5202DF0CCB}, // 1e302
	{0xD30560258F54E6BA, 0xBAA718E68396CFFD}, // 1e303
	{0x47C6B82EF32A2069, 0xE950DF20247C83FD}, // 1e304
	{0x4CDC331D57FA5441, 0x91D28B7416CDD27E}, // 1e305
	{0xE0133FE4ADF8E952, 0xB6472E511C81471D}, // 1e306
	{0x58180FDDD97723A6, 0xE3D8F9E563A198E5}, // 1e307
	{0x570F09EAA7EA7648, 0x8E679C2F5E44FF8F}, // 1e308
	{0x2CD2CC6551E513DA, 0xB201833B35D63F73}, // 1e309
	{0xF8077F7EA65E58D1, 0xDE81E40A034BCF4F}, // 1e310
	{0xFB04AFAF27FAF782, 0x8B112E86420F6191}, // 1e311
	{0x79C5DB9AF1F9B563, 0xADD57A27D29339F6}, // 1e312
	{0x18375281AE7822BC, 0xD94AD8B1C7380874}, // 1e313
	{0x8F2293910D0B15B5, 0x87CEC76F1C830548}, // 1e314
	{0xB2EB3875504DDB22, 0xA9C2794AE3A3C69A}, // 1e315
	{0x5FA60692A46151EB, 0xD433179D9C8CB841}, // 1e316
	{0xDBC7C41BA6BCD333, 0x849FEEC281D7F328}, // 1e317
	{0x12B9B522906C0800, 0xA5C7EA73224DEFF3}, // 1e318
	{0xD768226B34870A00, 0xCF39E50FEAE16BEF}, // 1e319
	{0xE6A1158300D46640, 0x81842F29F2CCE375}, // 1e320
	{0x60495AE3C1097FD0, 0xA1E53AF46F801C53}, // 1e321
	{0x385BB19CB14BDFC4, 0xCA5E89B18B602368}, // 1e322
	{0x46729E03DD9ED7B5, 0xFCF62C1DEE382C42}, // 1e323
	{0x6C07A2C26A8346D1, 0x9E19DB92B4E31BA9}, // 1e324
	{0xC7098B7305241885, 0xC5A05277621BE293}, // 1e325
	{0xB8CBEE4FC66D1EA7, 0xF70867153AA2DB38}, // 1e326
	{0x737F74F1DC043328, 0x9A65406D44A5C903}, // 1e327
	{0x505F522E53053FF2, 0xC0FE908895CF3B44}, // 1e328
	{0x647726B9E7C68FEF, 0xF13E34AABB430A15}, // 1e329
	{0x5ECA783430DC19F5, 0x96C6E0EAB509E64D}, // 1e330
	{0xB67D16413D132072, 0xBC789925624C5FE0}, // 1e331
	{0xE41C5BD18C57E88F, 0xEB96BF6EBADF77D8}, // 1e332
	{0x8E91B962F7B6F159, 0x933E37A534CBAAE7}, // 1e333
	{0x723627BBB5A4ADB0, 0xB80DC58E81FE95A1}, // 1e334
	{0xCEC3B1AAA30DD91C, 0xE61136F2227E3B09}, // 1e335
	{0x213A4F0AA5E8A7B1, 0x8FCAC257558EE4E6}, // 1e336
	{0xA988E2CD4F62D19D, 0xB3BD72ED2AF29E1F}, // 1e337
	{0x93EB1B80A33B8605, 0xE0ACCFA875AF45A7}, // 1e338
	{0xBC72F130660533C3, 0x8C6C01C9498D8B88}, // 1e339
	{0xEB8FAD7C7F8680B4, 0xAF87023B9BF0EE6A}, // 1e340
	{0xA67398DB9F6820E1, 0xDB68C2CA82ED2A05}, // 1e341
	{0x88083F8943A1148C, 0x892179BE91D43A43}, // 1e342
	{0x6A0A4F6B948959B0, 0xAB69D82E364948D4}, // 1e343
	{0x848CE34679ABB01C, 0xD6444E39C3DB9B09}, // 1e344
	{0xF2D80E0C0C0B4E11, 0x85EAB0E41A6940E5}, // 1e345
	{0x6F8E118F0F0E2195, 0xA7655D1D2103911F}, // 1e346
	{0x4B7195F2D2D1A9FB, 0xD13EB46469447567}, // 1e347
}
```