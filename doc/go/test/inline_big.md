Response: Let's break down the thought process to analyze the Go code and generate the explanation.

**1. Understanding the Goal:**

The initial prompt asks for an analysis of a Go file (`inline_big.go`) focusing on its functionality, the Go feature it demonstrates, code examples, logic explanation with input/output, command-line arguments (if any), and common mistakes.

**2. Initial Scan and Observations:**

* **Filename and Path:** `go/test/inline_big.go` suggests this is a test file within the Go compiler's testing infrastructure. The `inline_big` part hints at function inlining and size considerations.
* **`// errorcheck -0 -m=2`:** This is a crucial directive. It tells the Go test runner to check for specific compiler outputs. `-0` likely means no optimizations, and `-m=2` enables more detailed inlining information.
* **Copyright and License:** Standard Go boilerplate, not directly relevant to the functionality.
* **"Test that we restrict inlining into very large functions." and "See issue #26546."**: These comments directly state the purpose of the test. It's about preventing inlining into excessively large functions.
* **`package foo`:**  A simple package declaration, indicating this is a standalone test.
* **`func small(a []int) int { ... }`:** A small function that sums the first four elements of a slice. The `// ERROR "can inline small ..."` comment is key.
* **`func medium(a []int) int { ... }`:** A medium-sized function summing the first eight elements. Again, the `// ERROR "can inline medium ..."` comment is important.
* **`func f(a []int) int { ... }`:** A *very large* function that assigns 0 to the first 1000 elements of a slice, then calls `small` and `medium`. The `// ERROR "cannot inline f ..."` comment is the central point.

**3. Identifying the Core Concept:**

The comments and the structure of the code strongly point to the **function inlining** feature of the Go compiler. Specifically, it's testing the *limits* of inlining based on function size.

**4. Mapping Code to Inlining Concepts:**

* **`small`:**  Designed to be inlinable. The cost comment (`Cost 16 body (need cost < 20)`) and the `// ERROR "can inline"` confirm this.
* **`medium`:** Intended to be inlinable but with constraints. The cost comment (`Cost 32 body (need cost > 20 and cost < 80)`) and the `// ERROR "can inline"` suggest it meets certain inlining criteria but not others potentially related to size thresholds for the *caller*.
* **`f`:** Deliberately made huge. The comment `Add lots of nodes to f's body. We need >5000.` and the `// ERROR "cannot inline f ..."` confirm that it exceeds the inlining size limit. The error message also confirms that the *reason* for not inlining `f` is that it's considered "big".
* **Calls within `f`:** The calls to `small(a)` and `medium(a)` are where the inlining behavior will be tested. The comment "The crux of this test: medium is not inlined." is a vital clue.

**5. Formulating the Functionality Summary:**

Based on the observations, the code's primary function is to test the Go compiler's inlining behavior for functions of different sizes, specifically ensuring that very large functions are *not* inlined.

**6. Explaining the Go Feature (Inlining):**

Define function inlining and its purpose (performance improvement). Explain the compiler's decision-making process based on cost (size/complexity). Mention the trade-offs.

**7. Creating a Code Example:**

Provide a simple, runnable example demonstrating function inlining in general. This helps solidify the concept for the reader. A small function called from `main` is ideal.

**8. Explaining the Code Logic (with Assumptions):**

* **Input:**  A slice of integers.
* **`small`:** Sums the first four elements.
* **`medium`:** Sums the first eight elements.
* **`f`:** Modifies the first 1000 elements of the slice to 0, calls `small` and `medium`, and returns the sum of their results.
* **Output:** An integer.

**9. Addressing Command-Line Arguments:**

The `// errorcheck` directive uses flags, so explain their significance. `-0` disables optimizations, making inlining more predictable for testing. `-m=2` provides detailed inlining output, which is essential for verifying the test's correctness.

**10. Identifying Common Mistakes:**

Think about scenarios where developers might misunderstand or misuse inlining:

* **Over-reliance on manual inlining:** Go's compiler is generally good at this.
* **Assuming all small functions are always inlined:**  Context matters.
* **Not understanding the cost metric:** Developers don't usually see the cost, but it's the underlying factor.

**11. Review and Refine:**

Read through the entire explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have just said "it tests inlining," but refining it to "tests the *limits* of inlining for large functions" is more precise.

This iterative process of observation, deduction, and explanation, guided by the code comments and the `// errorcheck` directive, leads to a comprehensive understanding of the `inline_big.go` file and its purpose.
好的，让我们来归纳一下 `go/test/inline_big.go` 这个 Go 语言文件的功能。

**功能归纳**

`go/test/inline_big.go` 的主要功能是**测试 Go 编译器对于大型函数的内联限制**。  更具体地说，它验证了编译器在遇到非常大的函数时，会出于性能考虑而阻止将该函数内联到调用它的地方。

**推理 Go 语言功能：函数内联**

这个文件是用来测试 Go 语言的**函数内联 (Function Inlining)** 功能。函数内联是一种编译器优化技术，它将一个函数的调用替换为该函数实际的代码。这样做可以减少函数调用的开销，从而提高程序的执行效率。然而，对于非常大的函数，内联可能会导致代码膨胀，反而降低性能，或者增加编译时间。因此，Go 编译器会对可以内联的函数大小设置一定的阈值。

**Go 代码举例说明**

```go
package main

import "fmt"

func add(a, b int) int { // 小函数，很可能被内联
	return a + b
}

func multiplyAndAdd(a, b, c, d, e int) int { // 中等大小的函数，内联取决于编译器决定
	sum := a + b + c
	product := d * e
	return sum + product
}

func veryLargeFunction(n int) int { // 大型函数，很可能不会被内联
	sum := 0
	for i := 0; i < n; i++ {
		sum += i * i
	}
	// 假设这里有很多复杂的计算和逻辑，使得函数体非常庞大
	for i := 0; i < n; i++ {
		sum -= i
	}
	for i := 0; i < n; i++ {
		sum += i * 2
	}
	// ... 更多代码 ...
	return sum
}

func main() {
	x := 5
	y := 10
	result1 := add(x, y)
	result2 := multiplyAndAdd(1, 2, 3, 4, 5)
	result3 := veryLargeFunction(1000)
	fmt.Println(result1, result2, result3)
}
```

在这个例子中，`add` 函数非常小，编译器很可能会将其内联。`multiplyAndAdd` 函数的大小适中，编译器会根据其内部的“成本”来决定是否内联。而 `veryLargeFunction` 函数由于其循环和潜在的复杂逻辑，函数体非常大，编译器很可能会避免将其内联。

**代码逻辑介绍（带假设的输入与输出）**

`go/test/inline_big.go` 文件本身就是一个测试用例，它不直接执行程序逻辑，而是用来检查编译器的行为。

* **假设输入：**  Go 编译器在编译包含 `go/test/inline_big.go` 文件的代码时。
* **`small(a []int)` 函数：**
    * **假设输入:** `a` 是一个包含至少 4 个元素的整型切片，例如 `[]int{1, 2, 3, 4, 5}`。
    * **逻辑:** 返回切片 `a` 的前四个元素的和 (`a[0] + a[1] + a[2] + a[3]`)。
    * **预期输出:** 对于输入 `[]int{1, 2, 3, 4, 5}`，输出为 `1 + 2 + 3 + 4 = 10`。
* **`medium(a []int)` 函数：**
    * **假设输入:** `a` 是一个包含至少 8 个元素的整型切片，例如 `[]int{1, 2, 3, 4, 5, 6, 7, 8}`。
    * **逻辑:** 返回切片 `a` 的前八个元素的和。
    * **预期输出:** 对于输入 `[]int{1, 2, 3, 4, 5, 6, 7, 8}`，输出为 `1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 = 36`。
* **`f(a []int)` 函数：**
    * **假设输入:** `a` 是一个包含至少 1000 个元素的整型切片。
    * **逻辑:**
        1. 将切片 `a` 的前 1000 个元素都设置为 0。
        2. 调用 `small(a)`，由于 `a` 的前四个元素都是 0，所以 `small` 函数会返回 0。
        3. 调用 `medium(a)`，由于 `a` 的前八个元素都是 0，所以 `medium` 函数会返回 0。
        4. 返回 `small(a)` 和 `medium(a)` 的和，即 `0 + 0 = 0`。
    * **预期输出:** `0`。

**命令行参数的具体处理**

该文件开头的 `// errorcheck -0 -m=2` 就是在指定编译器的行为和输出。

* **`errorcheck`**:  这是一个 Go 编译器测试工具的指令，表明这是一个需要检查编译器错误或特定输出的测试文件。
* **`-0`**:  这个参数告诉编译器**禁用优化**。这很重要，因为内联本身就是一种优化。禁用其他优化可以更清晰地观察内联行为。
* **`-m=2`**: 这个参数指示编译器输出**更详细的内联决策信息**。当编译器决定内联或不内联某个函数时，它会打印出相关的原因和成本信息。

因此，当运行这个测试文件时，Go 的测试工具会使用指定的编译器参数来编译代码，并检查编译器的输出是否符合预期的错误信息（通过 `// ERROR ...` 注释指定）。

例如，对于 `func small(a []int) int` 行的 `// ERROR "can inline small with cost .* as:.*" "a does not escape"` 注释，测试工具会检查编译器在编译这段代码时，是否输出了包含 "can inline small with cost ..." 和 "a does not escape" 的信息，表明 `small` 函数被认为是可以内联的。

对于 `func f(a []int) int` 行的 `// ERROR "cannot inline f:.*" "a does not escape" "function f considered 'big'"` 注释，测试工具会检查编译器是否输出了包含 "cannot inline f:" 和 "function f considered 'big'" 的信息，证明编译器由于 `f` 函数过大而拒绝内联它。

**使用者易犯错的点**

由于 `go/test/inline_big.go` 是 Go 编译器自身的测试代码，普通 Go 开发者不会直接使用或修改它。然而，理解其背后的原理对于编写高性能的 Go 代码是有帮助的。

对于 Go 开发者来说，与函数内联相关的容易犯错的点可能包括：

1. **过度依赖手动内联：**  Go 编译器在内联方面已经做得相当不错了，通常不需要开发者手动进行复杂的调整。过分关注手动内联可能会导致代码可读性下降，维护困难，并且效果不一定比编译器自动优化好。

2. **期望所有小函数都被内联：**  即使函数很小，编译器也可能由于其他因素（例如，调用上下文、参数逃逸分析等）而选择不内联。开发者不应该假设所有“看起来很小”的函数都会被内联。

3. **不理解内联的“成本”概念：** 编译器在决定是否内联时会考虑函数的“成本”，这涉及到函数的大小、复杂性等因素。开发者可能无法直接看到这些成本值，但应该理解编译器会权衡内联带来的收益和风险。`go/test/inline_big.go` 中的注释就提到了成本的概念 (`Cost 16 body`, `Cost 32 body`)。

**总结**

`go/test/inline_big.go` 是 Go 编译器测试套件的一部分，专门用于验证编译器对于大型函数的内联限制。它通过定义不同大小的函数，并使用特定的编译器参数来检查编译器的内联决策输出，确保了 Go 编译器在处理大型函数时能够做出合理的优化选择，避免因过度内联导致性能下降。理解这个测试背后的原理有助于 Go 开发者更好地理解编译器的优化行为，从而编写出更高效的 Go 代码。

### 提示词
```
这是路径为go/test/inline_big.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// errorcheck -0 -m=2

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test that we restrict inlining into very large functions.
// See issue #26546.

package foo

func small(a []int) int { // ERROR "can inline small with cost .* as:.*" "a does not escape"
	// Cost 16 body (need cost < 20).
	// See cmd/compile/internal/gc/inl.go:inlineBigFunction*
	return a[0] + a[1] + a[2] + a[3]
}
func medium(a []int) int { // ERROR "can inline medium with cost .* as:.*" "a does not escape"
	// Cost 32 body (need cost > 20 and cost < 80).
	// See cmd/compile/internal/gc/inl.go:inlineBigFunction*
	return a[0] + a[1] + a[2] + a[3] + a[4] + a[5] + a[6] + a[7]
}

func f(a []int) int { // ERROR "cannot inline f:.*" "a does not escape" "function f considered 'big'"
	// Add lots of nodes to f's body. We need >5000.
	// See cmd/compile/internal/gc/inl.go:inlineBigFunction*
	a[0] = 0
	a[1] = 0
	a[2] = 0
	a[3] = 0
	a[4] = 0
	a[5] = 0
	a[6] = 0
	a[7] = 0
	a[8] = 0
	a[9] = 0
	a[10] = 0
	a[11] = 0
	a[12] = 0
	a[13] = 0
	a[14] = 0
	a[15] = 0
	a[16] = 0
	a[17] = 0
	a[18] = 0
	a[19] = 0
	a[20] = 0
	a[21] = 0
	a[22] = 0
	a[23] = 0
	a[24] = 0
	a[25] = 0
	a[26] = 0
	a[27] = 0
	a[28] = 0
	a[29] = 0
	a[30] = 0
	a[31] = 0
	a[32] = 0
	a[33] = 0
	a[34] = 0
	a[35] = 0
	a[36] = 0
	a[37] = 0
	a[38] = 0
	a[39] = 0
	a[40] = 0
	a[41] = 0
	a[42] = 0
	a[43] = 0
	a[44] = 0
	a[45] = 0
	a[46] = 0
	a[47] = 0
	a[48] = 0
	a[49] = 0
	a[50] = 0
	a[51] = 0
	a[52] = 0
	a[53] = 0
	a[54] = 0
	a[55] = 0
	a[56] = 0
	a[57] = 0
	a[58] = 0
	a[59] = 0
	a[60] = 0
	a[61] = 0
	a[62] = 0
	a[63] = 0
	a[64] = 0
	a[65] = 0
	a[66] = 0
	a[67] = 0
	a[68] = 0
	a[69] = 0
	a[70] = 0
	a[71] = 0
	a[72] = 0
	a[73] = 0
	a[74] = 0
	a[75] = 0
	a[76] = 0
	a[77] = 0
	a[78] = 0
	a[79] = 0
	a[80] = 0
	a[81] = 0
	a[82] = 0
	a[83] = 0
	a[84] = 0
	a[85] = 0
	a[86] = 0
	a[87] = 0
	a[88] = 0
	a[89] = 0
	a[90] = 0
	a[91] = 0
	a[92] = 0
	a[93] = 0
	a[94] = 0
	a[95] = 0
	a[96] = 0
	a[97] = 0
	a[98] = 0
	a[99] = 0
	a[100] = 0
	a[101] = 0
	a[102] = 0
	a[103] = 0
	a[104] = 0
	a[105] = 0
	a[106] = 0
	a[107] = 0
	a[108] = 0
	a[109] = 0
	a[110] = 0
	a[111] = 0
	a[112] = 0
	a[113] = 0
	a[114] = 0
	a[115] = 0
	a[116] = 0
	a[117] = 0
	a[118] = 0
	a[119] = 0
	a[120] = 0
	a[121] = 0
	a[122] = 0
	a[123] = 0
	a[124] = 0
	a[125] = 0
	a[126] = 0
	a[127] = 0
	a[128] = 0
	a[129] = 0
	a[130] = 0
	a[131] = 0
	a[132] = 0
	a[133] = 0
	a[134] = 0
	a[135] = 0
	a[136] = 0
	a[137] = 0
	a[138] = 0
	a[139] = 0
	a[140] = 0
	a[141] = 0
	a[142] = 0
	a[143] = 0
	a[144] = 0
	a[145] = 0
	a[146] = 0
	a[147] = 0
	a[148] = 0
	a[149] = 0
	a[150] = 0
	a[151] = 0
	a[152] = 0
	a[153] = 0
	a[154] = 0
	a[155] = 0
	a[156] = 0
	a[157] = 0
	a[158] = 0
	a[159] = 0
	a[160] = 0
	a[161] = 0
	a[162] = 0
	a[163] = 0
	a[164] = 0
	a[165] = 0
	a[166] = 0
	a[167] = 0
	a[168] = 0
	a[169] = 0
	a[170] = 0
	a[171] = 0
	a[172] = 0
	a[173] = 0
	a[174] = 0
	a[175] = 0
	a[176] = 0
	a[177] = 0
	a[178] = 0
	a[179] = 0
	a[180] = 0
	a[181] = 0
	a[182] = 0
	a[183] = 0
	a[184] = 0
	a[185] = 0
	a[186] = 0
	a[187] = 0
	a[188] = 0
	a[189] = 0
	a[190] = 0
	a[191] = 0
	a[192] = 0
	a[193] = 0
	a[194] = 0
	a[195] = 0
	a[196] = 0
	a[197] = 0
	a[198] = 0
	a[199] = 0
	a[200] = 0
	a[201] = 0
	a[202] = 0
	a[203] = 0
	a[204] = 0
	a[205] = 0
	a[206] = 0
	a[207] = 0
	a[208] = 0
	a[209] = 0
	a[210] = 0
	a[211] = 0
	a[212] = 0
	a[213] = 0
	a[214] = 0
	a[215] = 0
	a[216] = 0
	a[217] = 0
	a[218] = 0
	a[219] = 0
	a[220] = 0
	a[221] = 0
	a[222] = 0
	a[223] = 0
	a[224] = 0
	a[225] = 0
	a[226] = 0
	a[227] = 0
	a[228] = 0
	a[229] = 0
	a[230] = 0
	a[231] = 0
	a[232] = 0
	a[233] = 0
	a[234] = 0
	a[235] = 0
	a[236] = 0
	a[237] = 0
	a[238] = 0
	a[239] = 0
	a[240] = 0
	a[241] = 0
	a[242] = 0
	a[243] = 0
	a[244] = 0
	a[245] = 0
	a[246] = 0
	a[247] = 0
	a[248] = 0
	a[249] = 0
	a[250] = 0
	a[251] = 0
	a[252] = 0
	a[253] = 0
	a[254] = 0
	a[255] = 0
	a[256] = 0
	a[257] = 0
	a[258] = 0
	a[259] = 0
	a[260] = 0
	a[261] = 0
	a[262] = 0
	a[263] = 0
	a[264] = 0
	a[265] = 0
	a[266] = 0
	a[267] = 0
	a[268] = 0
	a[269] = 0
	a[270] = 0
	a[271] = 0
	a[272] = 0
	a[273] = 0
	a[274] = 0
	a[275] = 0
	a[276] = 0
	a[277] = 0
	a[278] = 0
	a[279] = 0
	a[280] = 0
	a[281] = 0
	a[282] = 0
	a[283] = 0
	a[284] = 0
	a[285] = 0
	a[286] = 0
	a[287] = 0
	a[288] = 0
	a[289] = 0
	a[290] = 0
	a[291] = 0
	a[292] = 0
	a[293] = 0
	a[294] = 0
	a[295] = 0
	a[296] = 0
	a[297] = 0
	a[298] = 0
	a[299] = 0
	a[300] = 0
	a[301] = 0
	a[302] = 0
	a[303] = 0
	a[304] = 0
	a[305] = 0
	a[306] = 0
	a[307] = 0
	a[308] = 0
	a[309] = 0
	a[310] = 0
	a[311] = 0
	a[312] = 0
	a[313] = 0
	a[314] = 0
	a[315] = 0
	a[316] = 0
	a[317] = 0
	a[318] = 0
	a[319] = 0
	a[320] = 0
	a[321] = 0
	a[322] = 0
	a[323] = 0
	a[324] = 0
	a[325] = 0
	a[326] = 0
	a[327] = 0
	a[328] = 0
	a[329] = 0
	a[330] = 0
	a[331] = 0
	a[332] = 0
	a[333] = 0
	a[334] = 0
	a[335] = 0
	a[336] = 0
	a[337] = 0
	a[338] = 0
	a[339] = 0
	a[340] = 0
	a[341] = 0
	a[342] = 0
	a[343] = 0
	a[344] = 0
	a[345] = 0
	a[346] = 0
	a[347] = 0
	a[348] = 0
	a[349] = 0
	a[350] = 0
	a[351] = 0
	a[352] = 0
	a[353] = 0
	a[354] = 0
	a[355] = 0
	a[356] = 0
	a[357] = 0
	a[358] = 0
	a[359] = 0
	a[360] = 0
	a[361] = 0
	a[362] = 0
	a[363] = 0
	a[364] = 0
	a[365] = 0
	a[366] = 0
	a[367] = 0
	a[368] = 0
	a[369] = 0
	a[370] = 0
	a[371] = 0
	a[372] = 0
	a[373] = 0
	a[374] = 0
	a[375] = 0
	a[376] = 0
	a[377] = 0
	a[378] = 0
	a[379] = 0
	a[380] = 0
	a[381] = 0
	a[382] = 0
	a[383] = 0
	a[384] = 0
	a[385] = 0
	a[386] = 0
	a[387] = 0
	a[388] = 0
	a[389] = 0
	a[390] = 0
	a[391] = 0
	a[392] = 0
	a[393] = 0
	a[394] = 0
	a[395] = 0
	a[396] = 0
	a[397] = 0
	a[398] = 0
	a[399] = 0
	a[400] = 0
	a[401] = 0
	a[402] = 0
	a[403] = 0
	a[404] = 0
	a[405] = 0
	a[406] = 0
	a[407] = 0
	a[408] = 0
	a[409] = 0
	a[410] = 0
	a[411] = 0
	a[412] = 0
	a[413] = 0
	a[414] = 0
	a[415] = 0
	a[416] = 0
	a[417] = 0
	a[418] = 0
	a[419] = 0
	a[420] = 0
	a[421] = 0
	a[422] = 0
	a[423] = 0
	a[424] = 0
	a[425] = 0
	a[426] = 0
	a[427] = 0
	a[428] = 0
	a[429] = 0
	a[430] = 0
	a[431] = 0
	a[432] = 0
	a[433] = 0
	a[434] = 0
	a[435] = 0
	a[436] = 0
	a[437] = 0
	a[438] = 0
	a[439] = 0
	a[440] = 0
	a[441] = 0
	a[442] = 0
	a[443] = 0
	a[444] = 0
	a[445] = 0
	a[446] = 0
	a[447] = 0
	a[448] = 0
	a[449] = 0
	a[450] = 0
	a[451] = 0
	a[452] = 0
	a[453] = 0
	a[454] = 0
	a[455] = 0
	a[456] = 0
	a[457] = 0
	a[458] = 0
	a[459] = 0
	a[460] = 0
	a[461] = 0
	a[462] = 0
	a[463] = 0
	a[464] = 0
	a[465] = 0
	a[466] = 0
	a[467] = 0
	a[468] = 0
	a[469] = 0
	a[470] = 0
	a[471] = 0
	a[472] = 0
	a[473] = 0
	a[474] = 0
	a[475] = 0
	a[476] = 0
	a[477] = 0
	a[478] = 0
	a[479] = 0
	a[480] = 0
	a[481] = 0
	a[482] = 0
	a[483] = 0
	a[484] = 0
	a[485] = 0
	a[486] = 0
	a[487] = 0
	a[488] = 0
	a[489] = 0
	a[490] = 0
	a[491] = 0
	a[492] = 0
	a[493] = 0
	a[494] = 0
	a[495] = 0
	a[496] = 0
	a[497] = 0
	a[498] = 0
	a[499] = 0
	a[500] = 0
	a[501] = 0
	a[502] = 0
	a[503] = 0
	a[504] = 0
	a[505] = 0
	a[506] = 0
	a[507] = 0
	a[508] = 0
	a[509] = 0
	a[510] = 0
	a[511] = 0
	a[512] = 0
	a[513] = 0
	a[514] = 0
	a[515] = 0
	a[516] = 0
	a[517] = 0
	a[518] = 0
	a[519] = 0
	a[520] = 0
	a[521] = 0
	a[522] = 0
	a[523] = 0
	a[524] = 0
	a[525] = 0
	a[526] = 0
	a[527] = 0
	a[528] = 0
	a[529] = 0
	a[530] = 0
	a[531] = 0
	a[532] = 0
	a[533] = 0
	a[534] = 0
	a[535] = 0
	a[536] = 0
	a[537] = 0
	a[538] = 0
	a[539] = 0
	a[540] = 0
	a[541] = 0
	a[542] = 0
	a[543] = 0
	a[544] = 0
	a[545] = 0
	a[546] = 0
	a[547] = 0
	a[548] = 0
	a[549] = 0
	a[550] = 0
	a[551] = 0
	a[552] = 0
	a[553] = 0
	a[554] = 0
	a[555] = 0
	a[556] = 0
	a[557] = 0
	a[558] = 0
	a[559] = 0
	a[560] = 0
	a[561] = 0
	a[562] = 0
	a[563] = 0
	a[564] = 0
	a[565] = 0
	a[566] = 0
	a[567] = 0
	a[568] = 0
	a[569] = 0
	a[570] = 0
	a[571] = 0
	a[572] = 0
	a[573] = 0
	a[574] = 0
	a[575] = 0
	a[576] = 0
	a[577] = 0
	a[578] = 0
	a[579] = 0
	a[580] = 0
	a[581] = 0
	a[582] = 0
	a[583] = 0
	a[584] = 0
	a[585] = 0
	a[586] = 0
	a[587] = 0
	a[588] = 0
	a[589] = 0
	a[590] = 0
	a[591] = 0
	a[592] = 0
	a[593] = 0
	a[594] = 0
	a[595] = 0
	a[596] = 0
	a[597] = 0
	a[598] = 0
	a[599] = 0
	a[600] = 0
	a[601] = 0
	a[602] = 0
	a[603] = 0
	a[604] = 0
	a[605] = 0
	a[606] = 0
	a[607] = 0
	a[608] = 0
	a[609] = 0
	a[610] = 0
	a[611] = 0
	a[612] = 0
	a[613] = 0
	a[614] = 0
	a[615] = 0
	a[616] = 0
	a[617] = 0
	a[618] = 0
	a[619] = 0
	a[620] = 0
	a[621] = 0
	a[622] = 0
	a[623] = 0
	a[624] = 0
	a[625] = 0
	a[626] = 0
	a[627] = 0
	a[628] = 0
	a[629] = 0
	a[630] = 0
	a[631] = 0
	a[632] = 0
	a[633] = 0
	a[634] = 0
	a[635] = 0
	a[636] = 0
	a[637] = 0
	a[638] = 0
	a[639] = 0
	a[640] = 0
	a[641] = 0
	a[642] = 0
	a[643] = 0
	a[644] = 0
	a[645] = 0
	a[646] = 0
	a[647] = 0
	a[648] = 0
	a[649] = 0
	a[650] = 0
	a[651] = 0
	a[652] = 0
	a[653] = 0
	a[654] = 0
	a[655] = 0
	a[656] = 0
	a[657] = 0
	a[658] = 0
	a[659] = 0
	a[660] = 0
	a[661] = 0
	a[662] = 0
	a[663] = 0
	a[664] = 0
	a[665] = 0
	a[666] = 0
	a[667] = 0
	a[668] = 0
	a[669] = 0
	a[670] = 0
	a[671] = 0
	a[672] = 0
	a[673] = 0
	a[674] = 0
	a[675] = 0
	a[676] = 0
	a[677] = 0
	a[678] = 0
	a[679] = 0
	a[680] = 0
	a[681] = 0
	a[682] = 0
	a[683] = 0
	a[684] = 0
	a[685] = 0
	a[686] = 0
	a[687] = 0
	a[688] = 0
	a[689] = 0
	a[690] = 0
	a[691] = 0
	a[692] = 0
	a[693] = 0
	a[694] = 0
	a[695] = 0
	a[696] = 0
	a[697] = 0
	a[698] = 0
	a[699] = 0
	a[700] = 0
	a[701] = 0
	a[702] = 0
	a[703] = 0
	a[704] = 0
	a[705] = 0
	a[706] = 0
	a[707] = 0
	a[708] = 0
	a[709] = 0
	a[710] = 0
	a[711] = 0
	a[712] = 0
	a[713] = 0
	a[714] = 0
	a[715] = 0
	a[716] = 0
	a[717] = 0
	a[718] = 0
	a[719] = 0
	a[720] = 0
	a[721] = 0
	a[722] = 0
	a[723] = 0
	a[724] = 0
	a[725] = 0
	a[726] = 0
	a[727] = 0
	a[728] = 0
	a[729] = 0
	a[730] = 0
	a[731] = 0
	a[732] = 0
	a[733] = 0
	a[734] = 0
	a[735] = 0
	a[736] = 0
	a[737] = 0
	a[738] = 0
	a[739] = 0
	a[740] = 0
	a[741] = 0
	a[742] = 0
	a[743] = 0
	a[744] = 0
	a[745] = 0
	a[746] = 0
	a[747] = 0
	a[748] = 0
	a[749] = 0
	a[750] = 0
	a[751] = 0
	a[752] = 0
	a[753] = 0
	a[754] = 0
	a[755] = 0
	a[756] = 0
	a[757] = 0
	a[758] = 0
	a[759] = 0
	a[760] = 0
	a[761] = 0
	a[762] = 0
	a[763] = 0
	a[764] = 0
	a[765] = 0
	a[766] = 0
	a[767] = 0
	a[768] = 0
	a[769] = 0
	a[770] = 0
	a[771] = 0
	a[772] = 0
	a[773] = 0
	a[774] = 0
	a[775] = 0
	a[776] = 0
	a[777] = 0
	a[778] = 0
	a[779] = 0
	a[780] = 0
	a[781] = 0
	a[782] = 0
	a[783] = 0
	a[784] = 0
	a[785] = 0
	a[786] = 0
	a[787] = 0
	a[788] = 0
	a[789] = 0
	a[790] = 0
	a[791] = 0
	a[792] = 0
	a[793] = 0
	a[794] = 0
	a[795] = 0
	a[796] = 0
	a[797] = 0
	a[798] = 0
	a[799] = 0
	a[800] = 0
	a[801] = 0
	a[802] = 0
	a[803] = 0
	a[804] = 0
	a[805] = 0
	a[806] = 0
	a[807] = 0
	a[808] = 0
	a[809] = 0
	a[810] = 0
	a[811] = 0
	a[812] = 0
	a[813] = 0
	a[814] = 0
	a[815] = 0
	a[816] = 0
	a[817] = 0
	a[818] = 0
	a[819] = 0
	a[820] = 0
	a[821] = 0
	a[822] = 0
	a[823] = 0
	a[824] = 0
	a[825] = 0
	a[826] = 0
	a[827] = 0
	a[828] = 0
	a[829] = 0
	a[830] = 0
	a[831] = 0
	a[832] = 0
	a[833] = 0
	a[834] = 0
	a[835] = 0
	a[836] = 0
	a[837] = 0
	a[838] = 0
	a[839] = 0
	a[840] = 0
	a[841] = 0
	a[842] = 0
	a[843] = 0
	a[844] = 0
	a[845] = 0
	a[846] = 0
	a[847] = 0
	a[848] = 0
	a[849] = 0
	a[850] = 0
	a[851] = 0
	a[852] = 0
	a[853] = 0
	a[854] = 0
	a[855] = 0
	a[856] = 0
	a[857] = 0
	a[858] = 0
	a[859] = 0
	a[860] = 0
	a[861] = 0
	a[862] = 0
	a[863] = 0
	a[864] = 0
	a[865] = 0
	a[866] = 0
	a[867] = 0
	a[868] = 0
	a[869] = 0
	a[870] = 0
	a[871] = 0
	a[872] = 0
	a[873] = 0
	a[874] = 0
	a[875] = 0
	a[876] = 0
	a[877] = 0
	a[878] = 0
	a[879] = 0
	a[880] = 0
	a[881] = 0
	a[882] = 0
	a[883] = 0
	a[884] = 0
	a[885] = 0
	a[886] = 0
	a[887] = 0
	a[888] = 0
	a[889] = 0
	a[890] = 0
	a[891] = 0
	a[892] = 0
	a[893] = 0
	a[894] = 0
	a[895] = 0
	a[896] = 0
	a[897] = 0
	a[898] = 0
	a[899] = 0
	a[900] = 0
	a[901] = 0
	a[902] = 0
	a[903] = 0
	a[904] = 0
	a[905] = 0
	a[906] = 0
	a[907] = 0
	a[908] = 0
	a[909] = 0
	a[910] = 0
	a[911] = 0
	a[912] = 0
	a[913] = 0
	a[914] = 0
	a[915] = 0
	a[916] = 0
	a[917] = 0
	a[918] = 0
	a[919] = 0
	a[920] = 0
	a[921] = 0
	a[922] = 0
	a[923] = 0
	a[924] = 0
	a[925] = 0
	a[926] = 0
	a[927] = 0
	a[928] = 0
	a[929] = 0
	a[930] = 0
	a[931] = 0
	a[932] = 0
	a[933] = 0
	a[934] = 0
	a[935] = 0
	a[936] = 0
	a[937] = 0
	a[938] = 0
	a[939] = 0
	a[940] = 0
	a[941] = 0
	a[942] = 0
	a[943] = 0
	a[944] = 0
	a[945] = 0
	a[946] = 0
	a[947] = 0
	a[948] = 0
	a[949] = 0
	a[950] = 0
	a[951] = 0
	a[952] = 0
	a[953] = 0
	a[954] = 0
	a[955] = 0
	a[956] = 0
	a[957] = 0
	a[958] = 0
	a[959] = 0
	a[960] = 0
	a[961] = 0
	a[962] = 0
	a[963] = 0
	a[964] = 0
	a[965] = 0
	a[966] = 0
	a[967] = 0
	a[968] = 0
	a[969] = 0
	a[970] = 0
	a[971] = 0
	a[972] = 0
	a[973] = 0
	a[974] = 0
	a[975] = 0
	a[976] = 0
	a[977] = 0
	a[978] = 0
	a[979] = 0
	a[980] = 0
	a[981] = 0
	a[982] = 0
	a[983] = 0
	a[984] = 0
	a[985] = 0
	a[986] = 0
	a[987] = 0
	a[988] = 0
	a[989] = 0
	a[990] = 0
	a[991] = 0
	a[992] = 0
	a[993] = 0
	a[994] = 0
	a[995] = 0
	a[996] = 0
	a[997] = 0
	a[998] = 0
	a[999] = 0
	x := small(a)  // ERROR "inlining call to small"
	y := medium(a) // The crux of this test: medium is not inlined.
	return x + y
}
```