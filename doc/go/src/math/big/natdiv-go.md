Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, its use cases, potential pitfalls, and a summary of its purpose. The title "Multi-precision division. Here be dragons." immediately suggests this code deals with arbitrary-precision arithmetic, specifically division.

2. **Initial Skim for Keywords and Structure:**  A quick scan reveals key terms like "division," "quo," "rem," "u," "v," "long division," "recursive division," "guess," "check," "scaling," and function names like `rem`, `div`, `divW`, `divLarge`, `divBasic`, `divRecursive`, `divRecursiveStep`. The comments are extensive and provide a high-level explanation of the algorithms.

3. **Identify Core Functions:**  The function signatures at the end of the snippet are crucial. `rem`, `div`, and `divW` are entry points. `divLarge`, `divBasic`, and `divRecursive` seem to be internal implementations of division. `divRecursiveStep` is clearly a helper for the recursive approach.

4. **Analyze `rem` and `div`:** These are the most straightforward.
    * `rem`: Calls `div` and extracts the remainder. This points to `div` being the primary division function.
    * `div`:  Handles basic cases (division by zero, `u < v`, single-word divisor) and then calls `divLarge` for the general case. This structure suggests optimizations for simpler scenarios.

5. **Deep Dive into `divLarge`:** This function handles the core logic for large numbers.
    * **Scaling:** The comments about "Scaling Inputs" are directly implemented here using `nlz` (number of leading zeros) and bitwise shifts (`shlVU`). This hints at an optimization to ensure the divisor has a significant leading digit for more accurate guesses.
    * **Algorithm Choice:** It selects between `divBasic` and `divRecursive` based on `divRecursiveThreshold`. This signifies two different algorithmic approaches.
    * **Normalization:**  Calls to `.norm()` suggest the `nat` type might have internal representation details that need adjustment (e.g., removing leading zeros).
    * **Remainder Handling:** The scaling is undone at the end (`shrVU`), reinforcing the idea of an initial scaling step.

6. **Explore `divW` and `modW`:** These functions are clearly for division by a single `Word`. This is an optimization for a common case. `modW` further simplifies by only returning the remainder. The helper `divWVW` performs the actual digit-by-digit division.

7. **Focus on `divBasic` (Long Division):** The comments provide a detailed explanation of the long division algorithm. Key steps to look for in the code:
    * **Guessing (`qhat`):**  The code calculates an initial guess.
    * **Refining:** The loop involving `greaterThan` implements the 3-by-2 guess refinement.
    * **Multiplication (`mulAddVWW`):**  Multiplies the guess by the divisor.
    * **Subtraction (`subVV`):** Subtracts the product from the current portion of the dividend.
    * **Fix-up:** The `if c != 0` block handles cases where the guess was too large.
    * **Quotient Accumulation:** The calculated `qhat` is stored in the `q` result.

8. **Understand `divRecursive` and `divRecursiveStep`:** The comments explain the recursive approach using "wide digits."
    * **Threshold:** `divRecursiveThreshold` determines when to switch to the recursive method.
    * **Wide Digits:** The concept of grouping digits is mentioned.
    * **Recursive Calls:**  `divRecursiveStep` calls itself, implementing the divide-and-conquer strategy.
    * **Base Case:**  It falls back to `divBasic` when the divisor is small enough.
    * **Temporary Storage:** The `temps` slice manages temporary `nat` values for each recursive level.

9. **Identify Potential Issues:**  The comments themselves highlight "Here be dragons," suggesting complexity and potential for errors. The "Scaling Inputs" section warns about the need to unscale the remainder. The guess-and-check mechanism in `divBasic` suggests potential for off-by-one errors if not implemented carefully. Aliasing between input and output parameters is handled explicitly, indicating it's a common concern.

10. **Structure the Answer:** Organize the findings logically. Start with a high-level summary, then detail the functionality of each key function. Use the comments as the primary source of information for explaining the algorithms. Provide a concrete Go example (as requested) to illustrate the usage. Mention the command-line aspects if relevant (though not in this particular snippet). Finally, address potential pitfalls based on the comments and code structure.

11. **Refine and Review:** Ensure the answer is clear, concise, and accurate. Use terminology consistent with the code and comments. Double-check the Go code example for correctness.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** "This looks like standard division."
* **Correction:** "No, the 'multi-precision' and the `nat` type suggest arbitrary-precision arithmetic, handling numbers larger than standard integer types."
* **Initial Thought:** "The code is just doing division."
* **Correction:** "The comments describe both basic long division and a more complex recursive approach. Need to differentiate these."
* **Initial Thought:** "The scaling seems arbitrary."
* **Correction:** "The comments explain the 'Good Guess Guarantee' and how scaling improves the accuracy of the initial guess in the long division algorithm."
* **Initial Thought:** "Just describe what the code does."
* **Correction:** "The prompt specifically asks for *reasoning* about the Go language features and *potential errors*. Need to go beyond just describing the code and explain the *why* and potential *problems*."

By following this structured approach, using the provided comments as a guide, and iteratively refining the understanding, a comprehensive answer addressing all aspects of the request can be generated.
好的，让我们来分析一下这段 Go 代码的功能。

**功能归纳**

这段 Go 代码实现了多精度（任意精度）整数的除法运算，包括计算商和余数。  它提供了两种主要的除法算法：

1. **基础长除法 (`divBasic`)**:  实现了类似于小学学习的竖式除法，按位计算商的每一位。为了提高效率，它采用了“猜测和检查”的策略来估计商的每一位，并进行了优化，例如通过缩放被除数和除数来改善猜测的准确性。

2. **递归除法 (`divRecursive`, `divRecursiveStep`)**: 对于非常大的数，递归地将除法问题分解为更小的子问题来提高效率。它将数字分组为“宽位”，并对这些宽位执行类似长除法的操作。当除数足够小时，会回退到基础长除法。

**更详细的功能分解**

* **`rem(u, v nat) (r nat)`**:  计算 `u` 除以 `v` 的余数。它内部调用 `div` 函数来计算商和余数，然后只返回余数。

* **`div(z nat, z2 nat, u nat, v nat) (q, r nat)`**:  计算 `u` 除以 `v` 的商（存储在 `z` 中）和余数（存储在 `z2` 中）。
    * 它处理了一些特殊情况，例如除数为零、被除数小于除数以及除数为单位数的情况，以进行优化。
    * 对于除数是单个字的情况，它调用 `divW` 进行高效的短除法。
    * 对于一般情况，它调用 `divLarge` 来处理。

* **`divW(x nat, y Word) (q nat, r Word)`**:  实现被除数 `x` 是多精度整数，除数 `y` 是单个机器字的情况下的除法，返回商 `q` 和余数 `r`。这是对单字除法的优化。

* **`modW(x nat, d Word) (r Word)`**:  计算多精度整数 `x` 除以单字 `d` 的余数。它内部调用 `divWVW`。

* **`divWVW(z []Word, xn Word, x []Word, y Word) (r Word)`**:  实际执行多精度整数 `x` 除以单字 `y` 的运算，将商写入 `z`，并返回余数 `r`。  它使用了硬件加速的 `bits.Div` 和优化的 `reciprocalWord` 计算。

* **`divLarge(z nat, uIn nat, vIn nat) (q, r nat)`**:  处理一般情况下的多精度除法。
    * 它首先对被除数 `uIn` 和除数 `vIn` 进行缩放，确保除数的最高位为 1，以提高后续“猜测”的准确性。
    * 然后根据除数的大小选择调用 `divBasic` (基础长除法) 或 `divRecursive` (递归除法)。
    * 最后，它会撤销之前的缩放，得到正确的余数。

* **`divBasic(q nat, u nat, v nat)`**:  实现基础的长除法算法。它通过循环计算商的每一位，使用“猜测和检查”来估计每一位的值，并进行必要的修正。

* **`divRecursive(z nat, u nat, v nat)`**:  `divRecursive` 是递归除法的入口。它负责分配和释放递归过程中使用的临时变量，并调用 `divRecursiveStep` 执行实际的递归计算。

* **`divRecursiveStep(z nat, u nat, v nat, depth int, tmp *nat, temps []*nat)`**:  实现递归除法的核心逻辑。它将大数的除法问题分解为更小的子问题，递归地进行计算。当除数足够小时，会调用 `divBasic` 回到基础的长除法。

**推理 Go 语言功能的实现**

这段代码主要实现了 Go 语言中 `math/big` 包中 `nat` 类型（表示自然数）的除法功能。`math/big` 包提供了任意精度的整数和浮点数运算，这在需要处理超出标准数据类型范围的大数时非常有用。

**Go 代码示例**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	u := new(big.Int)
	v := new(big.Int)
	q := new(big.Int)
	r := new(big.Int)

	u.SetString("12345678901234567890", 10)
	v.SetString("12345", 10)

	q.Div(u, v)
	r.Mod(u, v)

	fmt.Printf("商: %s\n", q.String())
	fmt.Printf("余数: %s\n", r.String())

	// 使用 nat 类型 (通常不直接使用，而是通过 big.Int 操作)
	natU := new(big.Int).Set(u).Bits() // 获取 big.Int 的 nat 表示
	natV := new(big.Int).Set(v).Bits()
	natQ := make(big.WordSlice, len(natU)) // 预分配空间
	natR := make(big.WordSlice, len(natU))

	// 注意：直接操作 nat 类型通常不推荐，这里仅为演示目的
	qNat, rNat := big.Nat(natQ).Div(big.Nat(natR), big.Nat(natU), big.Nat(natV))

	fmt.Printf("nat 商: %s\n", qNat.String())
	fmt.Printf("nat 余数: %s\n", rNat.String())
}
```

**假设的输入与输出**

在上面的代码示例中：

* **输入 `u` (被除数):** "12345678901234567890"
* **输入 `v` (除数):** "12345"

* **输出 `q` (商):** "1000055000855146"
* **输出 `r` (余数):** "11440"

对于 `nat` 类型的操作，输出也会是相同的数值，只是表示形式是 `big.WordSlice`。

**命令行参数处理**

这段代码本身并不直接处理命令行参数。它是一个底层的数值计算实现，通常被 `math/big` 包的其他部分调用。如果需要从命令行获取大数进行除法，你需要使用 `flag` 或其他库来解析命令行参数，并将字符串转换为 `big.Int` 类型。

**使用者易犯错的点**

1. **直接操作 `nat` 类型**:  虽然代码中展示了 `nat` 类型的操作，但通常情况下，开发者应该使用更高级别的 `big.Int` 类型进行操作。`nat` 类型是内部表示，直接操作容易出错且难以理解。

2. **忽略余数**:  在某些情况下，用户可能只关心商，而忽略余数。如果需要精确的计算，务必同时考虑商和余数。

3. **性能考虑**:  对于非常大的数，除法运算可能会比较耗时。用户应该了解不同算法（`divBasic` 和 `divRecursive`）的性能特点，并根据实际情况进行选择（虽然 `math/big` 包会自动选择）。

**总结它的功能**

这段代码是 Go 语言 `math/big` 包中用于执行多精度整数除法运算的核心实现。它提供了两种算法：一种是模拟传统竖式除法的基本长除法，另一种是针对大数优化的递归除法。  这段代码负责计算给定两个任意精度的自然数的商和余数，是 `math/big` 包提供高精度计算能力的关键组成部分。

Prompt: 
```
这是路径为go/src/math/big/natdiv.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*

Multi-precision division. Here be dragons.

Given u and v, where u is n+m digits, and v is n digits (with no leading zeros),
the goal is to return quo, rem such that u = quo*v + rem, where 0 ≤ rem < v.
That is, quo = ⌊u/v⌋ where ⌊x⌋ denotes the floor (truncation to integer) of x,
and rem = u - quo·v.


Long Division

Division in a computer proceeds the same as long division in elementary school,
but computers are not as good as schoolchildren at following vague directions,
so we have to be much more precise about the actual steps and what can happen.

We work from most to least significant digit of the quotient, doing:

 • Guess a digit q, the number of v to subtract from the current
   section of u to zero out the topmost digit.
 • Check the guess by multiplying q·v and comparing it against
   the current section of u, adjusting the guess as needed.
 • Subtract q·v from the current section of u.
 • Add q to the corresponding section of the result quo.

When all digits have been processed, the final remainder is left in u
and returned as rem.

For example, here is a sketch of dividing 5 digits by 3 digits (n=3, m=2).

	                 q₂ q₁ q₀
	         _________________
	v₂ v₁ v₀ ) u₄ u₃ u₂ u₁ u₀
	           ↓  ↓  ↓  |  |
	          [u₄ u₃ u₂]|  |
	        - [  q₂·v  ]|  |
	        ----------- ↓  |
	          [  rem  | u₁]|
	        - [    q₁·v   ]|
	           ----------- ↓
	             [  rem  | u₀]
	           - [    q₀·v   ]
	              ------------
	                [  rem   ]

Instead of creating new storage for the remainders and copying digits from u
as indicated by the arrows, we use u's storage directly as both the source
and destination of the subtractions, so that the remainders overwrite
successive overlapping sections of u as the division proceeds, using a slice
of u to identify the current section. This avoids all the copying as well as
shifting of remainders.

Division of u with n+m digits by v with n digits (in base B) can in general
produce at most m+1 digits, because:

  • u < B^(n+m)               [B^(n+m) has n+m+1 digits]
  • v ≥ B^(n-1)               [B^(n-1) is the smallest n-digit number]
  • u/v < B^(n+m) / B^(n-1)   [divide bounds for u, v]
  • u/v < B^(m+1)             [simplify]

The first step is special: it takes the top n digits of u and divides them by
the n digits of v, producing the first quotient digit and an n-digit remainder.
In the example, q₂ = ⌊u₄u₃u₂ / v⌋.

The first step divides n digits by n digits to ensure that it produces only a
single digit.

Each subsequent step appends the next digit from u to the remainder and divides
those n+1 digits by the n digits of v, producing another quotient digit and a
new n-digit remainder.

Subsequent steps divide n+1 digits by n digits, an operation that in general
might produce two digits. However, as used in the algorithm, that division is
guaranteed to produce only a single digit. The dividend is of the form
rem·B + d, where rem is a remainder from the previous step and d is a single
digit, so:

 • rem ≤ v - 1                 [rem is a remainder from dividing by v]
 • rem·B ≤ v·B - B             [multiply by B]
 • d ≤ B - 1                   [d is a single digit]
 • rem·B + d ≤ v·B - 1         [add]
 • rem·B + d < v·B             [change ≤ to <]
 • (rem·B + d)/v < B           [divide by v]


Guess and Check

At each step we need to divide n+1 digits by n digits, but this is for the
implementation of division by n digits, so we can't just invoke a division
routine: we _are_ the division routine. Instead, we guess at the answer and
then check it using multiplication. If the guess is wrong, we correct it.

How can this guessing possibly be efficient? It turns out that the following
statement (let's call it the Good Guess Guarantee) is true.

If

 • q = ⌊u/v⌋ where u is n+1 digits and v is n digits,
 • q < B, and
 • the topmost digit of v = vₙ₋₁ ≥ B/2,

then q̂ = ⌊uₙuₙ₋₁ / vₙ₋₁⌋ satisfies q ≤ q̂ ≤ q+2. (Proof below.)

That is, if we know the answer has only a single digit and we guess an answer
by ignoring the bottom n-1 digits of u and v, using a 2-by-1-digit division,
then that guess is at least as large as the correct answer. It is also not
too much larger: it is off by at most two from the correct answer.

Note that in the first step of the overall division, which is an n-by-n-digit
division, the 2-by-1 guess uses an implicit uₙ = 0.

Note that using a 2-by-1-digit division here does not mean calling ourselves
recursively. Instead, we use an efficient direct hardware implementation of
that operation.

Note that because q is u/v rounded down, q·v must not exceed u: u ≥ q·v.
If a guess q̂ is too big, it will not satisfy this test. Viewed a different way,
the remainder r̂ for a given q̂ is u - q̂·v, which must be positive. If it is
negative, then the guess q̂ is too big.

This gives us a way to compute q. First compute q̂ with 2-by-1-digit division.
Then, while u < q̂·v, decrement q̂; this loop executes at most twice, because
q̂ ≤ q+2.


Scaling Inputs

The Good Guess Guarantee requires that the top digit of v (vₙ₋₁) be at least B/2.
For example in base 10, ⌊172/19⌋ = 9, but ⌊18/1⌋ = 18: the guess is wildly off
because the first digit 1 is smaller than B/2 = 5.

We can ensure that v has a large top digit by multiplying both u and v by the
right amount. Continuing the example, if we multiply both 172 and 19 by 3, we
now have ⌊516/57⌋, the leading digit of v is now ≥ 5, and sure enough
⌊51/5⌋ = 10 is much closer to the correct answer 9. It would be easier here
to multiply by 4, because that can be done with a shift. Specifically, we can
always count the number of leading zeros i in the first digit of v and then
shift both u and v left by i bits.

Having scaled u and v, the value ⌊u/v⌋ is unchanged, but the remainder will
be scaled: 172 mod 19 is 1, but 516 mod 57 is 3. We have to divide the remainder
by the scaling factor (shifting right i bits) when we finish.

Note that these shifts happen before and after the entire division algorithm,
not at each step in the per-digit iteration.

Note the effect of scaling inputs on the size of the possible quotient.
In the scaled u/v, u can gain a digit from scaling; v never does, because we
pick the scaling factor to make v's top digit larger but without overflowing.
If u and v have n+m and n digits after scaling, then:

  • u < B^(n+m)               [B^(n+m) has n+m+1 digits]
  • v ≥ B^n / 2               [vₙ₋₁ ≥ B/2, so vₙ₋₁·B^(n-1) ≥ B^n/2]
  • u/v < B^(n+m) / (B^n / 2) [divide bounds for u, v]
  • u/v < 2 B^m               [simplify]

The quotient can still have m+1 significant digits, but if so the top digit
must be a 1. This provides a different way to handle the first digit of the
result: compare the top n digits of u against v and fill in either a 0 or a 1.


Refining Guesses

Before we check whether u < q̂·v, we can adjust our guess to change it from
q̂ = ⌊uₙuₙ₋₁ / vₙ₋₁⌋ into the refined guess ⌊uₙuₙ₋₁uₙ₋₂ / vₙ₋₁vₙ₋₂⌋.
Although not mentioned above, the Good Guess Guarantee also promises that this
3-by-2-digit division guess is more precise and at most one away from the real
answer q. The improvement from the 2-by-1 to the 3-by-2 guess can also be done
without n-digit math.

If we have a guess q̂ = ⌊uₙuₙ₋₁ / vₙ₋₁⌋ and we want to see if it also equal to
⌊uₙuₙ₋₁uₙ₋₂ / vₙ₋₁vₙ₋₂⌋, we can use the same check we would for the full division:
if uₙuₙ₋₁uₙ₋₂ < q̂·vₙ₋₁vₙ₋₂, then the guess is too large and should be reduced.

Checking uₙuₙ₋₁uₙ₋₂ < q̂·vₙ₋₁vₙ₋₂ is the same as uₙuₙ₋₁uₙ₋₂ - q̂·vₙ₋₁vₙ₋₂ < 0,
and

	uₙuₙ₋₁uₙ₋₂ - q̂·vₙ₋₁vₙ₋₂ = (uₙuₙ₋₁·B + uₙ₋₂) - q̂·(vₙ₋₁·B + vₙ₋₂)
	                          [splitting off the bottom digit]
	                      = (uₙuₙ₋₁ - q̂·vₙ₋₁)·B + uₙ₋₂ - q̂·vₙ₋₂
	                          [regrouping]

The expression (uₙuₙ₋₁ - q̂·vₙ₋₁) is the remainder of uₙuₙ₋₁ / vₙ₋₁.
If the initial guess returns both q̂ and its remainder r̂, then checking
whether uₙuₙ₋₁uₙ₋₂ < q̂·vₙ₋₁vₙ₋₂ is the same as checking r̂·B + uₙ₋₂ < q̂·vₙ₋₂.

If we find that r̂·B + uₙ₋₂ < q̂·vₙ₋₂, then we can adjust the guess by
decrementing q̂ and adding vₙ₋₁ to r̂. We repeat until r̂·B + uₙ₋₂ ≥ q̂·vₙ₋₂.
(As before, this fixup is only needed at most twice.)

Now that q̂ = ⌊uₙuₙ₋₁uₙ₋₂ / vₙ₋₁vₙ₋₂⌋, as mentioned above it is at most one
away from the correct q, and we've avoided doing any n-digit math.
(If we need the new remainder, it can be computed as r̂·B + uₙ₋₂ - q̂·vₙ₋₂.)

The final check u < q̂·v and the possible fixup must be done at full precision.
For random inputs, a fixup at this step is exceedingly rare: the 3-by-2 guess
is not often wrong at all. But still we must do the check. Note that since the
3-by-2 guess is off by at most 1, it can be convenient to perform the final
u < q̂·v as part of the computation of the remainder r = u - q̂·v. If the
subtraction underflows, decremeting q̂ and adding one v back to r is enough to
arrive at the final q, r.

That's the entirety of long division: scale the inputs, and then loop over
each output position, guessing, checking, and correcting the next output digit.

For a 2n-digit number divided by an n-digit number (the worst size-n case for
division complexity), this algorithm uses n+1 iterations, each of which must do
at least the 1-by-n-digit multiplication q̂·v. That's O(n) iterations of
O(n) time each, so O(n²) time overall.


Recursive Division

For very large inputs, it is possible to improve on the O(n²) algorithm.
Let's call a group of n/2 real digits a (very) “wide digit”. We can run the
standard long division algorithm explained above over the wide digits instead of
the actual digits. This will result in many fewer steps, but the math involved in
each step is more work.

Where basic long division uses a 2-by-1-digit division to guess the initial q̂,
the new algorithm must use a 2-by-1-wide-digit division, which is of course
really an n-by-n/2-digit division. That's OK: if we implement n-digit division
in terms of n/2-digit division, the recursion will terminate when the divisor
becomes small enough to handle with standard long division or even with the
2-by-1 hardware instruction.

For example, here is a sketch of dividing 10 digits by 4, proceeding with
wide digits corresponding to two regular digits. The first step, still special,
must leave off a (regular) digit, dividing 5 by 4 and producing a 4-digit
remainder less than v. The middle steps divide 6 digits by 4, guaranteed to
produce two output digits each (one wide digit) with 4-digit remainders.
The final step must use what it has: the 4-digit remainder plus one more,
5 digits to divide by 4.

	                       q₆ q₅ q₄ q₃ q₂ q₁ q₀
	            _______________________________
	v₃ v₂ v₁ v₀ ) u₉ u₈ u₇ u₆ u₅ u₄ u₃ u₂ u₁ u₀
	              ↓  ↓  ↓  ↓  ↓  |  |  |  |  |
	             [u₉ u₈ u₇ u₆ u₅]|  |  |  |  |
	           - [    q₆q₅·v    ]|  |  |  |  |
	           ----------------- ↓  ↓  |  |  |
	                [    rem    |u₄ u₃]|  |  |
	              - [     q₄q₃·v      ]|  |  |
	              -------------------- ↓  ↓  |
	                      [    rem    |u₂ u₁]|
	                    - [     q₂q₁·v      ]|
	                    -------------------- ↓
	                            [    rem    |u₀]
	                          - [     q₀·v     ]
	                          ------------------
	                               [    rem    ]

An alternative would be to look ahead to how well n/2 divides into n+m and
adjust the first step to use fewer digits as needed, making the first step
more special to make the last step not special at all. For example, using the
same input, we could choose to use only 4 digits in the first step, leaving
a full wide digit for the last step:

	                       q₆ q₅ q₄ q₃ q₂ q₁ q₀
	            _______________________________
	v₃ v₂ v₁ v₀ ) u₉ u₈ u₇ u₆ u₅ u₄ u₃ u₂ u₁ u₀
	              ↓  ↓  ↓  ↓  |  |  |  |  |  |
	             [u₉ u₈ u₇ u₆]|  |  |  |  |  |
	           - [    q₆·v   ]|  |  |  |  |  |
	           -------------- ↓  ↓  |  |  |  |
	             [    rem    |u₅ u₄]|  |  |  |
	           - [     q₅q₄·v      ]|  |  |  |
	           -------------------- ↓  ↓  |  |
	                   [    rem    |u₃ u₂]|  |
	                 - [     q₃q₂·v      ]|  |
	                 -------------------- ↓  ↓
	                         [    rem    |u₁ u₀]
	                       - [     q₁q₀·v      ]
	                       ---------------------
	                               [    rem    ]

Today, the code in divRecursiveStep works like the first example. Perhaps in
the future we will make it work like the alternative, to avoid a special case
in the final iteration.

Either way, each step is a 3-by-2-wide-digit division approximated first by
a 2-by-1-wide-digit division, just as we did for regular digits in long division.
Because the actual answer we want is a 3-by-2-wide-digit division, instead of
multiplying q̂·v directly during the fixup, we can use the quick refinement
from long division (an n/2-by-n/2 multiply) to correct q to its actual value
and also compute the remainder (as mentioned above), and then stop after that,
never doing a full n-by-n multiply.

Instead of using an n-by-n/2-digit division to produce n/2 digits, we can add
(not discard) one more real digit, doing an (n+1)-by-(n/2+1)-digit division that
produces n/2+1 digits. That single extra digit tightens the Good Guess Guarantee
to q ≤ q̂ ≤ q+1 and lets us drop long division's special treatment of the first
digit. These benefits are discussed more after the Good Guess Guarantee proof
below.


How Fast is Recursive Division?

For a 2n-by-n-digit division, this algorithm runs a 4-by-2 long division over
wide digits, producing two wide digits plus a possible leading regular digit 1,
which can be handled without a recursive call. That is, the algorithm uses two
full iterations, each using an n-by-n/2-digit division and an n/2-by-n/2-digit
multiplication, along with a few n-digit additions and subtractions. The standard
n-by-n-digit multiplication algorithm requires O(n²) time, making the overall
algorithm require time T(n) where

	T(n) = 2T(n/2) + O(n) + O(n²)

which, by the Bentley-Haken-Saxe theorem, ends up reducing to T(n) = O(n²).
This is not an improvement over regular long division.

When the number of digits n becomes large enough, Karatsuba's algorithm for
multiplication can be used instead, which takes O(n^log₂3) = O(n^1.6) time.
(Karatsuba multiplication is implemented in func karatsuba in nat.go.)
That makes the overall recursive division algorithm take O(n^1.6) time as well,
which is an improvement, but again only for large enough numbers.

It is not critical to make sure that every recursion does only two recursive
calls. While in general the number of recursive calls can change the time
analysis, in this case doing three calls does not change the analysis:

	T(n) = 3T(n/2) + O(n) + O(n^log₂3)

ends up being T(n) = O(n^log₂3). Because the Karatsuba multiplication taking
time O(n^log₂3) is itself doing 3 half-sized recursions, doing three for the
division does not hurt the asymptotic performance. Of course, it is likely
still faster in practice to do two.


Proof of the Good Guess Guarantee

Given numbers x, y, let us break them into the quotients and remainders when
divided by some scaling factor S, with the added constraints that the quotient
x/y and the high part of y are both less than some limit T, and that the high
part of y is at least half as big as T.

	x₁ = ⌊x/S⌋        y₁ = ⌊y/S⌋
	x₀ = x mod S      y₀ = y mod S

	x  = x₁·S + x₀    0 ≤ x₀ < S    x/y < T
	y  = y₁·S + y₀    0 ≤ y₀ < S    T/2 ≤ y₁ < T

And consider the two truncated quotients:

	q = ⌊x/y⌋
	q̂ = ⌊x₁/y₁⌋

We will prove that q ≤ q̂ ≤ q+2.

The guarantee makes no real demands on the scaling factor S: it is simply the
magnitude of the digits cut from both x and y to produce x₁ and y₁.
The guarantee makes only limited demands on T: it must be large enough to hold
the quotient x/y, and y₁ must have roughly the same size.

To apply to the earlier discussion of 2-by-1 guesses in long division,
we would choose:

	S  = Bⁿ⁻¹
	T  = B
	x  = u
	x₁ = uₙuₙ₋₁
	x₀ = uₙ₋₂...u₀
	y  = v
	y₁ = vₙ₋₁
	y₀ = vₙ₋₂...u₀

These simpler variables avoid repeating those longer expressions in the proof.

Note also that, by definition, truncating division ⌊x/y⌋ satisfies

	x/y - 1 < ⌊x/y⌋ ≤ x/y.

This fact will be used a few times in the proofs.

Proof that q ≤ q̂:

	q̂·y₁ = ⌊x₁/y₁⌋·y₁                      [by definition, q̂ = ⌊x₁/y₁⌋]
	     > (x₁/y₁ - 1)·y₁                  [x₁/y₁ - 1 < ⌊x₁/y₁⌋]
	     = x₁ - y₁                         [distribute y₁]

	So q̂·y₁ > x₁ - y₁.
	Since q̂·y₁ is an integer, q̂·y₁ ≥ x₁ - y₁ + 1.

	q̂ - q = q̂ - ⌊x/y⌋                      [by definition, q = ⌊x/y⌋]
	      ≥ q̂ - x/y                        [⌊x/y⌋ < x/y]
	      = (1/y)·(q̂·y - x)                [factor out 1/y]
	      ≥ (1/y)·(q̂·y₁·S - x)             [y = y₁·S + y₀ ≥ y₁·S]
	      ≥ (1/y)·((x₁ - y₁ + 1)·S - x)    [above: q̂·y₁ ≥ x₁ - y₁ + 1]
	      = (1/y)·(x₁·S - y₁·S + S - x)    [distribute S]
	      = (1/y)·(S - x₀ - y₁·S)          [-x = -x₁·S - x₀]
	      > -y₁·S / y                      [x₀ < S, so S - x₀ > 0; drop it]
	      ≥ -1                             [y₁·S ≤ y]

	So q̂ - q > -1.
	Since q̂ - q is an integer, q̂ - q ≥ 0, or equivalently q ≤ q̂.

Proof that q̂ ≤ q+2:

	x₁/y₁ - x/y = x₁·S/y₁·S - x/y          [multiply left term by S/S]
	            ≤ x/y₁·S - x/y             [x₁S ≤ x]
	            = (x/y)·(y/y₁·S - 1)       [factor out x/y]
	            = (x/y)·((y - y₁·S)/y₁·S)  [move -1 into y/y₁·S fraction]
	            = (x/y)·(y₀/y₁·S)          [y - y₁·S = y₀]
	            = (x/y)·(1/y₁)·(y₀/S)      [factor out 1/y₁]
	            < (x/y)·(1/y₁)             [y₀ < S, so y₀/S < 1]
	            ≤ (x/y)·(2/T)              [y₁ ≥ T/2, so 1/y₁ ≤ 2/T]
	            < T·(2/T)                  [x/y < T]
	            = 2                        [T·(2/T) = 2]

	So x₁/y₁ - x/y < 2.

	q̂ - q = ⌊x₁/y₁⌋ - q                    [by definition, q̂ = ⌊x₁/y₁⌋]
	      = ⌊x₁/y₁⌋ - ⌊x/y⌋                [by definition, q = ⌊x/y⌋]
	      ≤ x₁/y₁ - ⌊x/y⌋                  [⌊x₁/y₁⌋ ≤ x₁/y₁]
	      < x₁/y₁ - (x/y - 1)              [⌊x/y⌋ > x/y - 1]
	      = (x₁/y₁ - x/y) + 1              [regrouping]
	      < 2 + 1                          [above: x₁/y₁ - x/y < 2]
	      = 3

	So q̂ - q < 3.
	Since q̂ - q is an integer, q̂ - q ≤ 2.

Note that when x/y < T/2, the bounds tighten to x₁/y₁ - x/y < 1 and therefore
q̂ - q ≤ 1.

Note also that in the general case 2n-by-n division where we don't know that
x/y < T, we do know that x/y < 2T, yielding the bound q̂ - q ≤ 4. So we could
remove the special case first step of long division as long as we allow the
first fixup loop to run up to four times. (Using a simple comparison to decide
whether the first digit is 0 or 1 is still more efficient, though.)

Finally, note that when dividing three leading base-B digits by two (scaled),
we have T = B² and x/y < B = T/B, a much tighter bound than x/y < T.
This in turn yields the much tighter bound x₁/y₁ - x/y < 2/B. This means that
⌊x₁/y₁⌋ and ⌊x/y⌋ can only differ when x/y is less than 2/B greater than an
integer. For random x and y, the chance of this is 2/B, or, for large B,
approximately zero. This means that after we produce the 3-by-2 guess in the
long division algorithm, the fixup loop essentially never runs.

In the recursive algorithm, the extra digit in (2·⌊n/2⌋+1)-by-(⌊n/2⌋+1)-digit
division has exactly the same effect: the probability of needing a fixup is the
same 2/B. Even better, we can allow the general case x/y < 2T and the fixup
probability only grows to 4/B, still essentially zero.


References

There are no great references for implementing long division; thus this comment.
Here are some notes about what to expect from the obvious references.

Knuth Volume 2 (Seminumerical Algorithms) section 4.3.1 is the usual canonical
reference for long division, but that entire series is highly compressed, never
repeating a necessary fact and leaving important insights to the exercises.
For example, no rationale whatsoever is given for the calculation that extends
q̂ from a 2-by-1 to a 3-by-2 guess, nor why it reduces the error bound.
The proof that the calculation even has the desired effect is left to exercises.
The solutions to those exercises provided at the back of the book are entirely
calculations, still with no explanation as to what is going on or how you would
arrive at the idea of doing those exact calculations. Nowhere is it mentioned
that this test extends the 2-by-1 guess into a 3-by-2 guess. The proof of the
Good Guess Guarantee is only for the 2-by-1 guess and argues by contradiction,
making it difficult to understand how modifications like adding another digit
or adjusting the quotient range affects the overall bound.

All that said, Knuth remains the canonical reference. It is dense but packed
full of information and references, and the proofs are simpler than many other
presentations. The proofs above are reworkings of Knuth's to remove the
arguments by contradiction and add explanations or steps that Knuth omitted.
But beware of errors in older printings. Take the published errata with you.

Brinch Hansen's “Multiple-length Division Revisited: a Tour of the Minefield”
starts with a blunt critique of Knuth's presentation (among others) and then
presents a more detailed and easier to follow treatment of long division,
including an implementation in Pascal. But the algorithm and implementation
work entirely in terms of 3-by-2 division, which is much less useful on modern
hardware than an algorithm using 2-by-1 division. The proofs are a bit too
focused on digit counting and seem needlessly complex, especially compared to
the ones given above.

Burnikel and Ziegler's “Fast Recursive Division” introduced the key insight of
implementing division by an n-digit divisor using recursive calls to division
by an n/2-digit divisor, relying on Karatsuba multiplication to yield a
sub-quadratic run time. However, the presentation decisions are made almost
entirely for the purpose of simplifying the run-time analysis, rather than
simplifying the presentation. Instead of a single algorithm that loops over
quotient digits, the paper presents two mutually-recursive algorithms, for
2n-by-n and 3n-by-2n. The paper also does not present any general (n+m)-by-n
algorithm.

The proofs in the paper are remarkably complex, especially considering that
the algorithm is at its core just long division on wide digits, so that the
usual long division proofs apply essentially unaltered.
*/

package big

import "math/bits"

// rem returns r such that r = u%v.
// It uses z as the storage for r.
func (z nat) rem(u, v nat) (r nat) {
	if alias(z, u) {
		z = nil
	}
	qp := getNat(0)
	q, r := qp.div(z, u, v)
	*qp = q
	putNat(qp)
	return r
}

// div returns q, r such that q = ⌊u/v⌋ and r = u%v = u - q·v.
// It uses z and z2 as the storage for q and r.
func (z nat) div(z2, u, v nat) (q, r nat) {
	if len(v) == 0 {
		panic("division by zero")
	}

	if u.cmp(v) < 0 {
		q = z[:0]
		r = z2.set(u)
		return
	}

	if len(v) == 1 {
		// Short division: long optimized for a single-word divisor.
		// In that case, the 2-by-1 guess is all we need at each step.
		var r2 Word
		q, r2 = z.divW(u, v[0])
		r = z2.setWord(r2)
		return
	}

	q, r = z.divLarge(z2, u, v)
	return
}

// divW returns q, r such that q = ⌊x/y⌋ and r = x%y = x - q·y.
// It uses z as the storage for q.
// Note that y is a single digit (Word), not a big number.
func (z nat) divW(x nat, y Word) (q nat, r Word) {
	m := len(x)
	switch {
	case y == 0:
		panic("division by zero")
	case y == 1:
		q = z.set(x) // result is x
		return
	case m == 0:
		q = z[:0] // result is 0
		return
	}
	// m > 0
	z = z.make(m)
	r = divWVW(z, 0, x, y)
	q = z.norm()
	return
}

// modW returns x % d.
func (x nat) modW(d Word) (r Word) {
	// TODO(agl): we don't actually need to store the q value.
	var q nat
	q = q.make(len(x))
	return divWVW(q, 0, x, d)
}

// divWVW overwrites z with ⌊x/y⌋, returning the remainder r.
// The caller must ensure that len(z) = len(x).
func divWVW(z []Word, xn Word, x []Word, y Word) (r Word) {
	r = xn
	if len(x) == 1 {
		qq, rr := bits.Div(uint(r), uint(x[0]), uint(y))
		z[0] = Word(qq)
		return Word(rr)
	}
	rec := reciprocalWord(y)
	for i := len(z) - 1; i >= 0; i-- {
		z[i], r = divWW(r, x[i], y, rec)
	}
	return r
}

// div returns q, r such that q = ⌊uIn/vIn⌋ and r = uIn%vIn = uIn - q·vIn.
// It uses z and u as the storage for q and r.
// The caller must ensure that len(vIn) ≥ 2 (use divW otherwise)
// and that len(uIn) ≥ len(vIn) (the answer is 0, uIn otherwise).
func (z nat) divLarge(u, uIn, vIn nat) (q, r nat) {
	n := len(vIn)
	m := len(uIn) - n

	// Scale the inputs so vIn's top bit is 1 (see “Scaling Inputs” above).
	// vIn is treated as a read-only input (it may be in use by another
	// goroutine), so we must make a copy.
	// uIn is copied to u.
	shift := nlz(vIn[n-1])
	vp := getNat(n)
	v := *vp
	shlVU(v, vIn, shift)
	u = u.make(len(uIn) + 1)
	u[len(uIn)] = shlVU(u[:len(uIn)], uIn, shift)

	// The caller should not pass aliased z and u, since those are
	// the two different outputs, but correct just in case.
	if alias(z, u) {
		z = nil
	}
	q = z.make(m + 1)

	// Use basic or recursive long division depending on size.
	if n < divRecursiveThreshold {
		q.divBasic(u, v)
	} else {
		q.divRecursive(u, v)
	}
	putNat(vp)

	q = q.norm()

	// Undo scaling of remainder.
	shrVU(u, u, shift)
	r = u.norm()

	return q, r
}

// divBasic implements long division as described above.
// It overwrites q with ⌊u/v⌋ and overwrites u with the remainder r.
// q must be large enough to hold ⌊u/v⌋.
func (q nat) divBasic(u, v nat) {
	n := len(v)
	m := len(u) - n

	qhatvp := getNat(n + 1)
	qhatv := *qhatvp

	// Set up for divWW below, precomputing reciprocal argument.
	vn1 := v[n-1]
	rec := reciprocalWord(vn1)

	// Invent a leading 0 for u, for the first iteration.
	// Invariant: ujn == u[j+n] in each iteration.
	ujn := Word(0)

	// Compute each digit of quotient.
	for j := m; j >= 0; j-- {
		// Compute the 2-by-1 guess q̂.
		qhat := Word(_M)

		// ujn ≤ vn1, or else q̂ would be more than one digit.
		// For ujn == vn1, we set q̂ to the max digit M above.
		// Otherwise, we compute the 2-by-1 guess.
		if ujn != vn1 {
			var rhat Word
			qhat, rhat = divWW(ujn, u[j+n-1], vn1, rec)

			// Refine q̂ to a 3-by-2 guess. See “Refining Guesses” above.
			vn2 := v[n-2]
			x1, x2 := mulWW(qhat, vn2)
			ujn2 := u[j+n-2]
			for greaterThan(x1, x2, rhat, ujn2) { // x1x2 > r̂ u[j+n-2]
				qhat--
				prevRhat := rhat
				rhat += vn1
				// If r̂  overflows, then
				// r̂ u[j+n-2]v[n-1] is now definitely > x1 x2.
				if rhat < prevRhat {
					break
				}
				// TODO(rsc): No need for a full mulWW.
				// x2 += vn2; if x2 overflows, x1++
				x1, x2 = mulWW(qhat, vn2)
			}
		}

		// Compute q̂·v.
		qhatv[n] = mulAddVWW(qhatv[0:n], v, qhat, 0)
		qhl := len(qhatv)
		if j+qhl > len(u) && qhatv[n] == 0 {
			qhl--
		}

		// Subtract q̂·v from the current section of u.
		// If it underflows, q̂·v > u, which we fix up
		// by decrementing q̂ and adding v back.
		c := subVV(u[j:j+qhl], u[j:], qhatv)
		if c != 0 {
			c := addVV(u[j:j+n], u[j:], v)
			// If n == qhl, the carry from subVV and the carry from addVV
			// cancel out and don't affect u[j+n].
			if n < qhl {
				u[j+n] += c
			}
			qhat--
		}

		ujn = u[j+n-1]

		// Save quotient digit.
		// Caller may know the top digit is zero and not leave room for it.
		if j == m && m == len(q) && qhat == 0 {
			continue
		}
		q[j] = qhat
	}

	putNat(qhatvp)
}

// greaterThan reports whether the two digit numbers x1 x2 > y1 y2.
// TODO(rsc): In contradiction to most of this file, x1 is the high
// digit and x2 is the low digit. This should be fixed.
func greaterThan(x1, x2, y1, y2 Word) bool {
	return x1 > y1 || x1 == y1 && x2 > y2
}

// divRecursiveThreshold is the number of divisor digits
// at which point divRecursive is faster than divBasic.
const divRecursiveThreshold = 100

// divRecursive implements recursive division as described above.
// It overwrites z with ⌊u/v⌋ and overwrites u with the remainder r.
// z must be large enough to hold ⌊u/v⌋.
// This function is just for allocating and freeing temporaries
// around divRecursiveStep, the real implementation.
func (z nat) divRecursive(u, v nat) {
	// Recursion depth is (much) less than 2 log₂(len(v)).
	// Allocate a slice of temporaries to be reused across recursion,
	// plus one extra temporary not live across the recursion.
	recDepth := 2 * bits.Len(uint(len(v)))
	tmp := getNat(3 * len(v))
	temps := make([]*nat, recDepth)

	clear(z)
	z.divRecursiveStep(u, v, 0, tmp, temps)

	// Free temporaries.
	for _, n := range temps {
		if n != nil {
			putNat(n)
		}
	}
	putNat(tmp)
}

// divRecursiveStep is the actual implementation of recursive division.
// It adds ⌊u/v⌋ to z and overwrites u with the remainder r.
// z must be large enough to hold ⌊u/v⌋.
// It uses temps[depth] (allocating if needed) as a temporary live across
// the recursive call. It also uses tmp, but not live across the recursion.
func (z nat) divRecursiveStep(u, v nat, depth int, tmp *nat, temps []*nat) {
	// u is a subsection of the original and may have leading zeros.
	// TODO(rsc): The v = v.norm() is useless and should be removed.
	// We know (and require) that v's top digit is ≥ B/2.
	u = u.norm()
	v = v.norm()
	if len(u) == 0 {
		clear(z)
		return
	}

	// Fall back to basic division if the problem is now small enough.
	n := len(v)
	if n < divRecursiveThreshold {
		z.divBasic(u, v)
		return
	}

	// Nothing to do if u is shorter than v (implies u < v).
	m := len(u) - n
	if m < 0 {
		return
	}

	// We consider B digits in a row as a single wide digit.
	// (See “Recursive Division” above.)
	//
	// TODO(rsc): rename B to Wide, to avoid confusion with _B,
	// which is something entirely different.
	// TODO(rsc): Look into whether using ⌈n/2⌉ is better than ⌊n/2⌋.
	B := n / 2

	// Allocate a nat for qhat below.
	if temps[depth] == nil {
		temps[depth] = getNat(n) // TODO(rsc): Can be just B+1.
	} else {
		*temps[depth] = temps[depth].make(B + 1)
	}

	// Compute each wide digit of the quotient.
	//
	// TODO(rsc): Change the loop to be
	//	for j := (m+B-1)/B*B; j > 0; j -= B {
	// which will make the final step a regular step, letting us
	// delete what amounts to an extra copy of the loop body below.
	j := m
	for j > B {
		// Divide u[j-B:j+n] (3 wide digits) by v (2 wide digits).
		// First make the 2-by-1-wide-digit guess using a recursive call.
		// Then extend the guess to the full 3-by-2 (see “Refining Guesses”).
		//
		// For the 2-by-1-wide-digit guess, instead of doing 2B-by-B-digit,
		// we use a (2B+1)-by-(B+1) digit, which handles the possibility that
		// the result has an extra leading 1 digit as well as guaranteeing
		// that the computed q̂ will be off by at most 1 instead of 2.

		// s is the number of digits to drop from the 3B- and 2B-digit chunks.
		// We drop B-1 to be left with 2B+1 and B+1.
		s := (B - 1)

		// uu is the up-to-3B-digit section of u we are working on.
		uu := u[j-B:]

		// Compute the 2-by-1 guess q̂, leaving r̂ in uu[s:B+n].
		qhat := *temps[depth]
		clear(qhat)
		qhat.divRecursiveStep(uu[s:B+n], v[s:], depth+1, tmp, temps)
		qhat = qhat.norm()

		// Extend to a 3-by-2 quotient and remainder.
		// Because divRecursiveStep overwrote the top part of uu with
		// the remainder r̂, the full uu already contains the equivalent
		// of r̂·B + uₙ₋₂ from the “Refining Guesses” discussion.
		// Subtracting q̂·vₙ₋₂ from it will compute the full-length remainder.
		// If that subtraction underflows, q̂·v > u, which we fix up
		// by decrementing q̂ and adding v back, same as in long division.

		// TODO(rsc): Instead of subtract and fix-up, this code is computing
		// q̂·vₙ₋₂ and decrementing q̂ until that product is ≤ u.
		// But we can do the subtraction directly, as in the comment above
		// and in long division, because we know that q̂ is wrong by at most one.
		qhatv := tmp.make(3 * n)
		clear(qhatv)
		qhatv = qhatv.mul(qhat, v[:s])
		for i := 0; i < 2; i++ {
			e := qhatv.cmp(uu.norm())
			if e <= 0 {
				break
			}
			subVW(qhat, qhat, 1)
			c := subVV(qhatv[:s], qhatv[:s], v[:s])
			if len(qhatv) > s {
				subVW(qhatv[s:], qhatv[s:], c)
			}
			addAt(uu[s:], v[s:], 0)
		}
		if qhatv.cmp(uu.norm()) > 0 {
			panic("impossible")
		}
		c := subVV(uu[:len(qhatv)], uu[:len(qhatv)], qhatv)
		if c > 0 {
			subVW(uu[len(qhatv):], uu[len(qhatv):], c)
		}
		addAt(z, 
"""




```