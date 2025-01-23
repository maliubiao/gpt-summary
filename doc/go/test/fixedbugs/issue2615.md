Response: Let's break down the thought process for analyzing this Go code.

1. **Initial Scan and Keywords:**  The first thing I do is scan the code for obvious keywords and patterns. I see `package main`, `func test`, `func main`, `if/else if`, bitwise operations (`&`, `<<`), `uint64`, and a large number of `else if` statements. The comment `// Issue 2615: a long chain of else if's causes an overflow in the parser stack.` immediately jumps out as the primary purpose of this code.

2. **Understanding `test` Function:**  The comment above the `test` function says "test returns the index of the lowest set bit in a 256-bit vector." This is a crucial piece of information. I then examine the `test` function's logic. It takes a `[4]uint64` as input, which represents 256 bits (4 * 64). The function then proceeds with a massive chain of `else if` statements. Each `else if` checks if a specific bit is set. The order of these checks is from the least significant bit to the most significant bit. The function returns the index of the *first* bit it finds that is set.

3. **Understanding the `main` Function:** The `main` function's purpose is clearly to *test* the `test` function. It iterates from 0 to 255. Inside the loop:
    * It initializes a `bits` array of four `uint64`s with all bits set to 1.
    * It then proceeds to *clear* the bottom `i` bits. The bit manipulation here is a little tricky at first glance, but it's systematically clearing bits. The `bits[i/64]` part selects the correct `uint64` in the array, and `1<<(uint(i)&63) - 1` creates a mask with the bottom `i % 64` bits set. XORing clears these bits. The inner loop ensures that all the preceding `uint64`s are set to 0.
    * It calls the `test` function with the modified `bits` array.
    * It compares the result of `test(bits)` with the expected value `i`. If they don't match, it prints an error and panics.

4. **Connecting `test` and `main`:** The `main` function is designed to create specific bit patterns where only the *i-th* bit is set (after clearing the lower bits). The `test` function is then expected to return `i` because that's the index of the lowest set bit.

5. **Identifying the "Issue":** The long chain of `else if` statements in `test` and the comment about "parser stack overflow" point directly to the core issue. This code is designed to *trigger* a potential problem in the Go compiler's parser when dealing with deeply nested conditional statements. It's not necessarily how you'd *normally* write code to find the lowest set bit.

6. **Inferring the Go Feature:** Based on the issue being about the parser and the structure of the code, the underlying Go feature being tested is the compiler's ability to handle complex conditional logic, particularly long chains of `if/else if` statements.

7. **Generating the Example:** To illustrate the functionality, a simple example demonstrating how the `test` function identifies the lowest set bit is needed. I would create a `main` function that calls `test` with different input arrays and prints the results. This would show the basic function of the code without the complexity of the original `main` function.

8. **Explaining the Code Logic:**  I would describe the `test` function as iterating through the bits and returning the index of the first set bit. For the `main` function, I would explain how it systematically creates bit patterns with a single set bit and verifies the output of the `test` function. I'd choose a specific iteration (e.g., `i = 10`) as a concrete example, showing the state of the `bits` array and the expected output.

9. **Command-line Arguments:**  A quick scan reveals that this code doesn't use any command-line arguments. The `main` function is self-contained.

10. **Common Mistakes:** The most obvious "mistake" here is writing such a long chain of `if/else if` statements. It's inefficient and difficult to read. A better approach would use bitwise operations and potentially a loop. This directly leads to the explanation of a more efficient way to achieve the same result.

11. **Review and Refine:** Finally, I would review the entire explanation for clarity, accuracy, and completeness, ensuring that all aspects of the prompt are addressed. For instance, double-checking the bit manipulation in `main` to ensure the explanation is correct.

This step-by-step process, starting with a high-level overview and gradually diving into the details, helps to thoroughly understand the code and address all the requirements of the prompt. The key is to connect the code structure with the problem it's designed to highlight (the parser stack overflow).
这个 Go 语言文件 `issue2615.go` 的主要功能是**测试 Go 语言编译器在处理包含大量 `else if` 语句的代码时的能力，特别是为了验证是否会因为过多的 `else if` 导致解析器栈溢出**。

**它所实现的 Go 语言功能可以理解为：** **复杂条件分支的处理能力**。

**Go 代码举例说明：**

虽然这个文件本身就是一个很好的例子，但为了更清晰地说明它测试的是什么，我们可以简化一下，展示一个类似的场景：

```go
package main

import "fmt"

func checkValue(n int) string {
	if n == 1 {
		return "One"
	} else if n == 2 {
		return "Two"
	} else if n == 3 {
		return "Three"
	} // ... 可以有很多很多的 else if
	else if n == 100 {
		return "Hundred"
	} else {
		return "Other"
	}
}

func main() {
	fmt.Println(checkValue(1))
	fmt.Println(checkValue(50))
	fmt.Println(checkValue(100))
}
```

这个简化的例子展示了多个 `else if` 构成条件分支。`issue2615.go` 中的 `test` 函数就是将这个概念扩展到了极致，用大量的 `else if` 来检查一个 256 位向量中哪个位被设置了。

**代码逻辑介绍（带假设的输入与输出）：**

`issue2615.go` 中的 `test` 函数接收一个 `[4]uint64` 类型的参数 `x`，这个数组可以看作一个 256 位的向量（因为 `uint64` 是 64 位，4 个就是 256 位）。

函数的目标是找出 `x` 中**最低位被设置为 1 的位的索引**（从 0 开始计数）。

假设输入： `x := [4]uint64{0, 0, 0, 4}`

* 二进制表示：`x` 的最后一个元素 `x[3]` 是 4，其二进制表示是 `...00000100`。
* `test` 函数会从第一个 `if` 开始逐个判断。
* 它会检查 `x[0]` 的第 0 位是否为 1，然后第 1 位，以此类推，直到 `x[0]` 的第 63 位。
* 接着会检查 `x[1]` 的各位，然后 `x[2]` 的各位。
* 当检查到 `x[3]&(1<<2) != 0` 时，条件成立，因为 `1<<2` 是 4，与 `x[3]` (也是 4) 进行与运算不为 0。
* 此时函数返回 258 (64*3 + 2)。

假设输入： `x := [4]uint64{10, 0, 0, 0}`

* 二进制表示：`x[0]` 是 10，其二进制表示是 `...00001010`。
* `test` 函数会先检查 `x[0]&(1<<0) != 0` (检查最低位)，结果为 0。
* 然后检查 `x[0]&(1<<1) != 0` (检查第二低位)，结果为 10 & 2 = 2，不为 0。
* 此时函数返回 1。

**`main` 函数的逻辑：**

`main` 函数的主要目的是**系统地测试 `test` 函数在各种情况下的正确性**。

1. **初始化:** 它定义了一个常量 `ones`，其值为 `^uint64(0)`，也就是所有位都是 1 的 64 位无符号整数。
2. **循环测试:** 它使用一个从 0 到 255 的循环。循环变量 `i` 代表了我们期望的最低设置位的索引。
3. **构造测试数据:** 在每次循环中，它创建一个 `bits` 数组，初始时所有位都设置为 1。
4. **清除低位:** 关键步骤是清除 `bits` 中低于索引 `i` 的所有位。
   * `bits[i/64] ^= 1<<(uint(i)&63) - 1`: 这行代码巧妙地清除了 `bits` 数组中包含第 `i` 位的 `uint64` 元素中，低于第 `i` 位的那些位。
   * 内部循环 `for j := i/64 - 1; j >= 0; j-- { bits[j] = 0 }`:  这部分代码确保了在包含第 `i` 位的 `uint64` 元素之前的所有元素都被设置为 0。
5. **调用 `test` 函数:** 使用构造好的 `bits` 数组调用 `test` 函数。
6. **验证结果:** 比较 `test` 函数的返回值 `k` 和预期的值 `i`。如果两者不相等，则打印错误信息并 panic。

**假设 `i = 10` 的一次循环:**

* `bits` 初始化为 `{[...]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}}` (所有位都是 1)。
* `i/64` 是 0，所以操作的是 `bits[0]`。
* `uint(i)&63` 是 10。
* `1<<(uint(i)&63)` 是 `1 << 10`，也就是十进制的 1024。
* `1<<(uint(i)&63) - 1` 是 1023，其二进制表示是 `...0000001111111111` (低 10 位是 1)。
* `bits[0] ^= 1023` 会将 `bits[0]` 的低 10 位从 1 变为 0，其余位不变。
* 内部循环不会执行，因为 `i/64 - 1` 是 -1。
* 此时 `bits[0]` 的低 10 位为 0，第 10 位为 1，其余位为 1。`bits` 的其他元素都是全 1。
* 调用 `k := test(bits)`，由于 `bits[0]` 的第 10 位（索引为 10）是第一个被设置的位，`test` 函数应该返回 10。
* 如果 `k != i` (即 `k != 10`)，则会 panic。

**命令行参数的具体处理：**

这段代码本身不涉及任何命令行参数的处理。它是一个独立的 Go 程序，运行后会执行 `main` 函数中的逻辑进行测试。

**使用者易犯错的点：**

这段代码的主要目的不是给用户直接使用的，而是用来测试 Go 编译器本身的。因此，一般使用者不会直接使用或修改这段代码。

但是，如果有人尝试将 `test` 函数用于实际的查找最低设置位的需求，那么这种**使用大量的 `else if` 链的方式是非常低效且难以维护的**。

**举例说明易犯错的点（如果尝试实际使用 `test` 函数）：**

假设开发者想在一个更大的位向量中查找最低设置位，他们可能会尝试扩展 `test` 函数，加入更多的 `else if`。

```go
// 假设开发者想处理 512 位的向量
func test_extended(x [8]uint64) int {
	// ... 前面的 256 个 else if
	else if x[4]&(1<<0) != 0 {
		return 256
	} else if x[4]&(1<<1) != 0 {
		return 257
	}
	// ... 更多 else if 直到 511
	return -1
}
```

这样做会使代码变得极其冗长且容易出错。更好的方法是使用循环和位运算来高效地实现这个功能。

**更高效的实现方式：**

```go
func lowestSetBit(x [4]uint64) int {
	for i := 0; i < len(x); i++ {
		if x[i] != 0 {
			for j := 0; j < 64; j++ {
				if (x[i] >> j) & 1 == 1 {
					return i*64 + j
				}
			}
		}
	}
	return -1
}
```

总而言之，`issue2615.go` 是一个针对 Go 编译器特定问题的测试用例，它通过构造一个包含大量 `else if` 语句的函数来验证编译器在这种复杂情况下的解析能力，防止出现栈溢出等问题。它并不代表一种推荐的编程实践。

### 提示词
```
这是路径为go/test/fixedbugs/issue2615.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// run

// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Issue 2615: a long chain of else if's causes an overflow
// in the parser stack.

package main

// test returns the index of the lowest set bit in a 256-bit vector.
func test(x [4]uint64) int {
	if x[0]&(1<<0) != 0 {
		return 0
	} else if x[0]&(1<<1) != 0 {
		return 1
	} else if x[0]&(1<<2) != 0 {
		return 2
	} else if x[0]&(1<<3) != 0 {
		return 3
	} else if x[0]&(1<<4) != 0 {
		return 4
	} else if x[0]&(1<<5) != 0 {
		return 5
	} else if x[0]&(1<<6) != 0 {
		return 6
	} else if x[0]&(1<<7) != 0 {
		return 7
	} else if x[0]&(1<<8) != 0 {
		return 8
	} else if x[0]&(1<<9) != 0 {
		return 9
	} else if x[0]&(1<<10) != 0 {
		return 10
	} else if x[0]&(1<<11) != 0 {
		return 11
	} else if x[0]&(1<<12) != 0 {
		return 12
	} else if x[0]&(1<<13) != 0 {
		return 13
	} else if x[0]&(1<<14) != 0 {
		return 14
	} else if x[0]&(1<<15) != 0 {
		return 15
	} else if x[0]&(1<<16) != 0 {
		return 16
	} else if x[0]&(1<<17) != 0 {
		return 17
	} else if x[0]&(1<<18) != 0 {
		return 18
	} else if x[0]&(1<<19) != 0 {
		return 19
	} else if x[0]&(1<<20) != 0 {
		return 20
	} else if x[0]&(1<<21) != 0 {
		return 21
	} else if x[0]&(1<<22) != 0 {
		return 22
	} else if x[0]&(1<<23) != 0 {
		return 23
	} else if x[0]&(1<<24) != 0 {
		return 24
	} else if x[0]&(1<<25) != 0 {
		return 25
	} else if x[0]&(1<<26) != 0 {
		return 26
	} else if x[0]&(1<<27) != 0 {
		return 27
	} else if x[0]&(1<<28) != 0 {
		return 28
	} else if x[0]&(1<<29) != 0 {
		return 29
	} else if x[0]&(1<<30) != 0 {
		return 30
	} else if x[0]&(1<<31) != 0 {
		return 31
	} else if x[0]&(1<<32) != 0 {
		return 32
	} else if x[0]&(1<<33) != 0 {
		return 33
	} else if x[0]&(1<<34) != 0 {
		return 34
	} else if x[0]&(1<<35) != 0 {
		return 35
	} else if x[0]&(1<<36) != 0 {
		return 36
	} else if x[0]&(1<<37) != 0 {
		return 37
	} else if x[0]&(1<<38) != 0 {
		return 38
	} else if x[0]&(1<<39) != 0 {
		return 39
	} else if x[0]&(1<<40) != 0 {
		return 40
	} else if x[0]&(1<<41) != 0 {
		return 41
	} else if x[0]&(1<<42) != 0 {
		return 42
	} else if x[0]&(1<<43) != 0 {
		return 43
	} else if x[0]&(1<<44) != 0 {
		return 44
	} else if x[0]&(1<<45) != 0 {
		return 45
	} else if x[0]&(1<<46) != 0 {
		return 46
	} else if x[0]&(1<<47) != 0 {
		return 47
	} else if x[0]&(1<<48) != 0 {
		return 48
	} else if x[0]&(1<<49) != 0 {
		return 49
	} else if x[0]&(1<<50) != 0 {
		return 50
	} else if x[0]&(1<<51) != 0 {
		return 51
	} else if x[0]&(1<<52) != 0 {
		return 52
	} else if x[0]&(1<<53) != 0 {
		return 53
	} else if x[0]&(1<<54) != 0 {
		return 54
	} else if x[0]&(1<<55) != 0 {
		return 55
	} else if x[0]&(1<<56) != 0 {
		return 56
	} else if x[0]&(1<<57) != 0 {
		return 57
	} else if x[0]&(1<<58) != 0 {
		return 58
	} else if x[0]&(1<<59) != 0 {
		return 59
	} else if x[0]&(1<<60) != 0 {
		return 60
	} else if x[0]&(1<<61) != 0 {
		return 61
	} else if x[0]&(1<<62) != 0 {
		return 62
	} else if x[0]&(1<<63) != 0 {
		return 63
	} else if x[1]&(1<<0) != 0 {
		return 64
	} else if x[1]&(1<<1) != 0 {
		return 65
	} else if x[1]&(1<<2) != 0 {
		return 66
	} else if x[1]&(1<<3) != 0 {
		return 67
	} else if x[1]&(1<<4) != 0 {
		return 68
	} else if x[1]&(1<<5) != 0 {
		return 69
	} else if x[1]&(1<<6) != 0 {
		return 70
	} else if x[1]&(1<<7) != 0 {
		return 71
	} else if x[1]&(1<<8) != 0 {
		return 72
	} else if x[1]&(1<<9) != 0 {
		return 73
	} else if x[1]&(1<<10) != 0 {
		return 74
	} else if x[1]&(1<<11) != 0 {
		return 75
	} else if x[1]&(1<<12) != 0 {
		return 76
	} else if x[1]&(1<<13) != 0 {
		return 77
	} else if x[1]&(1<<14) != 0 {
		return 78
	} else if x[1]&(1<<15) != 0 {
		return 79
	} else if x[1]&(1<<16) != 0 {
		return 80
	} else if x[1]&(1<<17) != 0 {
		return 81
	} else if x[1]&(1<<18) != 0 {
		return 82
	} else if x[1]&(1<<19) != 0 {
		return 83
	} else if x[1]&(1<<20) != 0 {
		return 84
	} else if x[1]&(1<<21) != 0 {
		return 85
	} else if x[1]&(1<<22) != 0 {
		return 86
	} else if x[1]&(1<<23) != 0 {
		return 87
	} else if x[1]&(1<<24) != 0 {
		return 88
	} else if x[1]&(1<<25) != 0 {
		return 89
	} else if x[1]&(1<<26) != 0 {
		return 90
	} else if x[1]&(1<<27) != 0 {
		return 91
	} else if x[1]&(1<<28) != 0 {
		return 92
	} else if x[1]&(1<<29) != 0 {
		return 93
	} else if x[1]&(1<<30) != 0 {
		return 94
	} else if x[1]&(1<<31) != 0 {
		return 95
	} else if x[1]&(1<<32) != 0 {
		return 96
	} else if x[1]&(1<<33) != 0 {
		return 97
	} else if x[1]&(1<<34) != 0 {
		return 98
	} else if x[1]&(1<<35) != 0 {
		return 99
	} else if x[1]&(1<<36) != 0 {
		return 100
	} else if x[1]&(1<<37) != 0 {
		return 101
	} else if x[1]&(1<<38) != 0 {
		return 102
	} else if x[1]&(1<<39) != 0 {
		return 103
	} else if x[1]&(1<<40) != 0 {
		return 104
	} else if x[1]&(1<<41) != 0 {
		return 105
	} else if x[1]&(1<<42) != 0 {
		return 106
	} else if x[1]&(1<<43) != 0 {
		return 107
	} else if x[1]&(1<<44) != 0 {
		return 108
	} else if x[1]&(1<<45) != 0 {
		return 109
	} else if x[1]&(1<<46) != 0 {
		return 110
	} else if x[1]&(1<<47) != 0 {
		return 111
	} else if x[1]&(1<<48) != 0 {
		return 112
	} else if x[1]&(1<<49) != 0 {
		return 113
	} else if x[1]&(1<<50) != 0 {
		return 114
	} else if x[1]&(1<<51) != 0 {
		return 115
	} else if x[1]&(1<<52) != 0 {
		return 116
	} else if x[1]&(1<<53) != 0 {
		return 117
	} else if x[1]&(1<<54) != 0 {
		return 118
	} else if x[1]&(1<<55) != 0 {
		return 119
	} else if x[1]&(1<<56) != 0 {
		return 120
	} else if x[1]&(1<<57) != 0 {
		return 121
	} else if x[1]&(1<<58) != 0 {
		return 122
	} else if x[1]&(1<<59) != 0 {
		return 123
	} else if x[1]&(1<<60) != 0 {
		return 124
	} else if x[1]&(1<<61) != 0 {
		return 125
	} else if x[1]&(1<<62) != 0 {
		return 126
	} else if x[1]&(1<<63) != 0 {
		return 127
	} else if x[2]&(1<<0) != 0 {
		return 128
	} else if x[2]&(1<<1) != 0 {
		return 129
	} else if x[2]&(1<<2) != 0 {
		return 130
	} else if x[2]&(1<<3) != 0 {
		return 131
	} else if x[2]&(1<<4) != 0 {
		return 132
	} else if x[2]&(1<<5) != 0 {
		return 133
	} else if x[2]&(1<<6) != 0 {
		return 134
	} else if x[2]&(1<<7) != 0 {
		return 135
	} else if x[2]&(1<<8) != 0 {
		return 136
	} else if x[2]&(1<<9) != 0 {
		return 137
	} else if x[2]&(1<<10) != 0 {
		return 138
	} else if x[2]&(1<<11) != 0 {
		return 139
	} else if x[2]&(1<<12) != 0 {
		return 140
	} else if x[2]&(1<<13) != 0 {
		return 141
	} else if x[2]&(1<<14) != 0 {
		return 142
	} else if x[2]&(1<<15) != 0 {
		return 143
	} else if x[2]&(1<<16) != 0 {
		return 144
	} else if x[2]&(1<<17) != 0 {
		return 145
	} else if x[2]&(1<<18) != 0 {
		return 146
	} else if x[2]&(1<<19) != 0 {
		return 147
	} else if x[2]&(1<<20) != 0 {
		return 148
	} else if x[2]&(1<<21) != 0 {
		return 149
	} else if x[2]&(1<<22) != 0 {
		return 150
	} else if x[2]&(1<<23) != 0 {
		return 151
	} else if x[2]&(1<<24) != 0 {
		return 152
	} else if x[2]&(1<<25) != 0 {
		return 153
	} else if x[2]&(1<<26) != 0 {
		return 154
	} else if x[2]&(1<<27) != 0 {
		return 155
	} else if x[2]&(1<<28) != 0 {
		return 156
	} else if x[2]&(1<<29) != 0 {
		return 157
	} else if x[2]&(1<<30) != 0 {
		return 158
	} else if x[2]&(1<<31) != 0 {
		return 159
	} else if x[2]&(1<<32) != 0 {
		return 160
	} else if x[2]&(1<<33) != 0 {
		return 161
	} else if x[2]&(1<<34) != 0 {
		return 162
	} else if x[2]&(1<<35) != 0 {
		return 163
	} else if x[2]&(1<<36) != 0 {
		return 164
	} else if x[2]&(1<<37) != 0 {
		return 165
	} else if x[2]&(1<<38) != 0 {
		return 166
	} else if x[2]&(1<<39) != 0 {
		return 167
	} else if x[2]&(1<<40) != 0 {
		return 168
	} else if x[2]&(1<<41) != 0 {
		return 169
	} else if x[2]&(1<<42) != 0 {
		return 170
	} else if x[2]&(1<<43) != 0 {
		return 171
	} else if x[2]&(1<<44) != 0 {
		return 172
	} else if x[2]&(1<<45) != 0 {
		return 173
	} else if x[2]&(1<<46) != 0 {
		return 174
	} else if x[2]&(1<<47) != 0 {
		return 175
	} else if x[2]&(1<<48) != 0 {
		return 176
	} else if x[2]&(1<<49) != 0 {
		return 177
	} else if x[2]&(1<<50) != 0 {
		return 178
	} else if x[2]&(1<<51) != 0 {
		return 179
	} else if x[2]&(1<<52) != 0 {
		return 180
	} else if x[2]&(1<<53) != 0 {
		return 181
	} else if x[2]&(1<<54) != 0 {
		return 182
	} else if x[2]&(1<<55) != 0 {
		return 183
	} else if x[2]&(1<<56) != 0 {
		return 184
	} else if x[2]&(1<<57) != 0 {
		return 185
	} else if x[2]&(1<<58) != 0 {
		return 186
	} else if x[2]&(1<<59) != 0 {
		return 187
	} else if x[2]&(1<<60) != 0 {
		return 188
	} else if x[2]&(1<<61) != 0 {
		return 189
	} else if x[2]&(1<<62) != 0 {
		return 190
	} else if x[2]&(1<<63) != 0 {
		return 191
	} else if x[3]&(1<<0) != 0 {
		return 192
	} else if x[3]&(1<<1) != 0 {
		return 193
	} else if x[3]&(1<<2) != 0 {
		return 194
	} else if x[3]&(1<<3) != 0 {
		return 195
	} else if x[3]&(1<<4) != 0 {
		return 196
	} else if x[3]&(1<<5) != 0 {
		return 197
	} else if x[3]&(1<<6) != 0 {
		return 198
	} else if x[3]&(1<<7) != 0 {
		return 199
	} else if x[3]&(1<<8) != 0 {
		return 200
	} else if x[3]&(1<<9) != 0 {
		return 201
	} else if x[3]&(1<<10) != 0 {
		return 202
	} else if x[3]&(1<<11) != 0 {
		return 203
	} else if x[3]&(1<<12) != 0 {
		return 204
	} else if x[3]&(1<<13) != 0 {
		return 205
	} else if x[3]&(1<<14) != 0 {
		return 206
	} else if x[3]&(1<<15) != 0 {
		return 207
	} else if x[3]&(1<<16) != 0 {
		return 208
	} else if x[3]&(1<<17) != 0 {
		return 209
	} else if x[3]&(1<<18) != 0 {
		return 210
	} else if x[3]&(1<<19) != 0 {
		return 211
	} else if x[3]&(1<<20) != 0 {
		return 212
	} else if x[3]&(1<<21) != 0 {
		return 213
	} else if x[3]&(1<<22) != 0 {
		return 214
	} else if x[3]&(1<<23) != 0 {
		return 215
	} else if x[3]&(1<<24) != 0 {
		return 216
	} else if x[3]&(1<<25) != 0 {
		return 217
	} else if x[3]&(1<<26) != 0 {
		return 218
	} else if x[3]&(1<<27) != 0 {
		return 219
	} else if x[3]&(1<<28) != 0 {
		return 220
	} else if x[3]&(1<<29) != 0 {
		return 221
	} else if x[3]&(1<<30) != 0 {
		return 222
	} else if x[3]&(1<<31) != 0 {
		return 223
	} else if x[3]&(1<<32) != 0 {
		return 224
	} else if x[3]&(1<<33) != 0 {
		return 225
	} else if x[3]&(1<<34) != 0 {
		return 226
	} else if x[3]&(1<<35) != 0 {
		return 227
	} else if x[3]&(1<<36) != 0 {
		return 228
	} else if x[3]&(1<<37) != 0 {
		return 229
	} else if x[3]&(1<<38) != 0 {
		return 230
	} else if x[3]&(1<<39) != 0 {
		return 231
	} else if x[3]&(1<<40) != 0 {
		return 232
	} else if x[3]&(1<<41) != 0 {
		return 233
	} else if x[3]&(1<<42) != 0 {
		return 234
	} else if x[3]&(1<<43) != 0 {
		return 235
	} else if x[3]&(1<<44) != 0 {
		return 236
	} else if x[3]&(1<<45) != 0 {
		return 237
	} else if x[3]&(1<<46) != 0 {
		return 238
	} else if x[3]&(1<<47) != 0 {
		return 239
	} else if x[3]&(1<<48) != 0 {
		return 240
	} else if x[3]&(1<<49) != 0 {
		return 241
	} else if x[3]&(1<<50) != 0 {
		return 242
	} else if x[3]&(1<<51) != 0 {
		return 243
	} else if x[3]&(1<<52) != 0 {
		return 244
	} else if x[3]&(1<<53) != 0 {
		return 245
	} else if x[3]&(1<<54) != 0 {
		return 246
	} else if x[3]&(1<<55) != 0 {
		return 247
	} else if x[3]&(1<<56) != 0 {
		return 248
	} else if x[3]&(1<<57) != 0 {
		return 249
	} else if x[3]&(1<<58) != 0 {
		return 250
	} else if x[3]&(1<<59) != 0 {
		return 251
	} else if x[3]&(1<<60) != 0 {
		return 252
	} else if x[3]&(1<<61) != 0 {
		return 253
	} else if x[3]&(1<<62) != 0 {
		return 254
	} else if x[3]&(1<<63) != 0 {
		return 255
	}
	return -1
}

func main() {
	const ones = ^uint64(0)
	for i := 0; i < 256; i++ {
		bits := [4]uint64{ones, ones, ones, ones}

		// clear bottom i bits
		bits[i/64] ^= 1<<(uint(i)&63) - 1
		for j := i/64 - 1; j >= 0; j-- {
			bits[j] = 0
		}

		k := test(bits)
		if k != i {
			print("test(bits)=", k, " want ", i, "\n")
			panic("failed")
		}
	}
}
```