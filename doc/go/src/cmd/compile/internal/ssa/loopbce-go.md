Response:
My thinking process to answer the request about `loopbce.go` went something like this:

1. **Understand the Goal:** The user wants to know the functionality of the provided Go code snippet, ideally relating it to a larger Go feature, along with examples, potential issues, and command-line relevance.

2. **Initial Code Scan - Identify Key Structures and Functions:** I quickly scanned the code, looking for prominent data structures and function names. I noticed:
    * `indVarFlags` and `indVar`:  These clearly define a way to represent and store information about induction variables.
    * `parseIndVar`:  This function name strongly suggests it's responsible for identifying induction variables within the SSA representation.
    * `findIndVar`: This function name indicates a process of searching for induction variables within a function.

3. **Analyze `parseIndVar`:** I focused on `parseIndVar` first because it seemed like the fundamental building block. I observed:
    * It checks if a given `*Value` is a `OpPhi`. This is a crucial clue, as Phi nodes are used at the entry of loop blocks in SSA to merge values from different incoming paths.
    * It looks for a specific pattern: `Phi min nxt` where `nxt` is an addition operation (`OpAdd`) involving the Phi node itself. This pattern is characteristic of an induction variable being incremented in a loop.
    * It extracts the initial value (`min`) and the incremented value (`nxt`).
    * It returns `nil` values if the pattern isn't matched, indicating that the input is not recognized as an induction variable.

4. **Analyze `findIndVar`:** Next, I examined `findIndVar`. My observations were:
    * It iterates through the blocks (`f.Blocks`) of a function.
    * It specifically looks for `BlockIf` blocks with two predecessors. This suggests it's looking for the conditional branch at the loop header.
    * It checks the comparison operation (`OpLess`, `OpLeq`) in the `BlockIf`'s control. This is how loop termination conditions are expressed.
    * It calls `parseIndVar` to check if one of the operands of the comparison is a recognized induction variable.
    * It handles both ascending and descending loops.
    * It performs several checks related to loop structure (single predecessor for the loop entry, dominance of the increment operation).
    * It includes overflow/underflow checks for the induction variable.
    * It stores the found induction variable information in an `indVar` struct.

5. **Connect to a Go Feature - Loop Optimization:** Based on the code's focus on identifying and analyzing loops and incrementing variables, the most likely Go feature is loop optimization. Specifically, **bounds check elimination (BCE)** comes to mind. The comments mentioning overflow/underflow checks further reinforce this idea, as eliminating bounds checks requires proving that array or slice accesses are within valid bounds. The file name `loopbce.go` provides almost definitive confirmation.

6. **Construct the Explanation:**  With the core functionality identified as detecting induction variables for loop optimization, particularly BCE, I began to structure the answer:
    * **Main Functionality:** Start by stating the primary goal: identifying induction variables for optimization.
    * **Detailed Explanation of Functions:** Describe `parseIndVar` and `findIndVar` and their roles in identifying the structure of induction variables and loops.
    * **Connecting to BCE:** Explicitly explain how the identified induction variables are used in BCE to remove redundant bounds checks.
    * **Go Code Example:** Create a simple Go loop example that demonstrates a scenario where BCE would be beneficial. Show the SSA representation (conceptually) to illustrate how the induction variable is formed. Include the expected output, focusing on the *absence* of panics due to bounds check elimination.
    * **Assumptions and Inferences:** Clearly list the assumptions made during the analysis, such as the specific SSA representation and the goal of BCE.
    * **Command-Line Arguments:** Explain that this code is part of the compiler and doesn't directly interact with command-line arguments. However, mention compiler flags related to optimization.
    * **Common Mistakes:**  Provide an example of a situation that might prevent BCE, like modifying the loop variable in a way that breaks the predictable increment pattern. This directly relates to understanding the limitations of the induction variable detection.

7. **Refine and Review:** I reviewed the explanation for clarity, accuracy, and completeness. I made sure the Go code example was simple and illustrative. I also double-checked that the explanations of `parseIndVar` and `findIndVar` accurately reflected the code's logic. I ensured the link to BCE was clearly articulated.

This iterative process of examining the code, making inferences, and connecting it to higher-level Go concepts allowed me to construct a comprehensive and accurate answer to the user's request. The file name was a significant hint, but even without it, the code's structure strongly suggests its role in loop optimization.
这段 `go/src/cmd/compile/internal/ssa/loopbce.go` 代码片段是 Go 编译器中用于 **循环边界检查消除 (Loop Bound Check Elimination, Loop BCE)** 的一部分。它的主要功能是 **识别循环中的归纳变量 (Induction Variables)**。

**功能列表:**

1. **`parseIndVar(ind *Value) (min, inc, nxt *Value)`:**
   - 尝试解析给定的 SSA 值 `ind` 是否为一个有效的归纳变量。
   - 如果是，它会提取：
     - `min`: 归纳变量的最小值（起始值）。
     - `inc`: 归纳变量的增量值。
     - `nxt`: 归纳变量在每次循环迭代后的下一个值。
   - 它当前只检测符合特定模式的归纳变量：`(Phi min nxt)`，其中 `nxt` 是 `(Add inc ind)` 或 `(Add ind inc)`。
   - 如果无法解析，则返回 `(nil, nil, nil)`。

2. **`findIndVar(f *Func) []indVar`:**
   - 在给定的函数 `f` 中查找所有的归纳变量。
   - 它会遍历函数中的所有基本块 (`Block`)。
   - 它寻找满足特定模式的循环结构：
     ```
     loop:
       ind = (Phi min nxt),
       if ind < max
         then goto enter_loop
         else goto exit_loop

       enter_loop:
         // ... 循环体 ...
         nxt = inc + ind
         goto loop

       exit_loop:
     ```
   - 它会调用 `parseIndVar` 来检查潜在的归纳变量。
   - 它会进行一系列检查，以确保识别出的变量确实是一个满足 BCE 条件的归纳变量，例如：
     - 比较操作符是 `<` 或 `<=`。
     - 增量值是一个非零常量。
     - 增量的符号与比较方向一致。
     - 循环入口块只有一个前驱（循环头）。
     - 计算下一个值的块被循环入口块支配。
     - 检查归纳变量是否会溢出或下溢。
   - 它将找到的归纳变量的信息存储在 `indVar` 结构体中，并返回一个 `indVar` 切片。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 编译器优化的一部分，专注于 **循环边界检查消除 (Loop Bound Check Elimination, Loop BCE)**。

在 Go 语言中，访问数组或切片的元素时会进行边界检查，以防止越界访问导致程序崩溃。然而，在某些循环中，编译器可以静态地证明循环内的数组或切片访问不会超出其边界。在这种情况下，执行边界检查是冗余的，会降低程序的性能。

`loopbce.go` 中的代码负责识别循环中的归纳变量，这是进行 BCE 的关键一步。通过分析归纳变量的起始值、增量和终止条件，编译器可以推断出循环变量的取值范围，从而判断数组或切片访问是否安全，并消除不必要的边界检查。

**Go 代码举例说明:**

```go
package main

func main() {
	arr := [10]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	for i := 0; i < len(arr); i++ {
		arr[i] = i * 2 // 编译器可以通过分析归纳变量 i 消除这里的边界检查
	}
	println(arr[5])
}
```

**代码推理 (假设的输入与输出):**

假设 `findIndVar` 函数接收了上面 `main` 函数对应的 SSA 表示。

**输入 (部分 SSA，简化表示):**

```
b1: // 循环头
  v1 = Phi [v2, v3] // i
  v2 = ConstInt 0   // 初始值 0
  v4 = Len arr
  v5 = Less v1 v4
  If v5 goto b2 else b3

b2: // 循环体
  // ... 对 arr[v1] 进行操作 ...
  v6 = Add v1 (ConstInt 1)
  Goto b1

b3: // 循环出口
  // ...
```

**`parseIndVar` 的推理:**

当 `findIndVar` 遍历到 `b1` 块时，它会调用 `parseIndVar(v1)`。

- `v1` 是一个 `OpPhi` 节点。
- `v1.Args[0]` 是 `v2` (初始值 0)。
- `v1.Args[1]` 对应的路径会指向 `b2` 中的加法操作，假设为 `v6 = Add v1 (ConstInt 1)`。
- `parseIndVar` 会识别出 `min = v2` (常量 0), `inc = ConstInt 1` (常量 1), `nxt = v6`。

**`findIndVar` 的推理:**

- `findIndVar` 会识别出 `b1` 是一个 `BlockIf` 块，有两个前驱。
- 控制条件 `v5 = Less v1 v4` 是一个小于比较。
- 它会调用 `parseIndVar(v1)`，成功解析出归纳变量 `i`。
- 它会检查增量 `inc` (常量 1) 是非零常量。
- 它会检查循环结构是否符合预期。
- 它会检查溢出/下溢的可能性。在本例中，由于循环条件是 `i < len(arr)`，并且增量为 1，不太可能溢出。
- `findIndVar` 最终会返回一个包含描述归纳变量 `i` 的 `indVar` 结构体的切片。该结构体可能包含 `ind: v1`, `nxt: v6`, `min: v2`, `max: v4`, `entry: b2`, `flags: 0` (默认的包含最小值，不包含最大值，向上计数)。

**输出 (假设的 `indVar` 结构体):**

```
[]ssa.indVar{
	{
		ind:   &ssa.Value{Op: OpPhi, ...}, // 指向 v1
		nxt:   &ssa.Value{Op: OpAdd, ...}, // 指向 v6
		min:   &ssa.Value{Op: OpConstInt, AuxInt: 0, ...}, // 指向 v2
		max:   &ssa.Value{Op: OpLen, ...}, // 指向 v4 (len(arr))
		entry: &ssa.Block{Kind: BlockPlain, ...}, // 指向 b2
		flags: 0,
	},
}
```

**命令行参数:**

这段代码本身并不直接处理命令行参数。它作为 Go 编译器内部的一部分运行。然而，Go 编译器的优化行为可以通过一些命令行参数来控制，例如：

- **`-gcflags`**:  允许向 Go 编译器传递参数。例如，可以使用 `-gcflags="-d=ssa/loopbce/debug=1"` 来启用 `loopbce` 相关的调试信息。
- **`-N`**:  禁用所有优化，包括循环边界检查消除。例如，`go build -gcflags="-N" main.go` 将禁用优化。
- **`-l`**:  禁用内联，这可能会影响某些优化的效果，因为内联会改变函数的 SSA 表示。

**使用者易犯错的点:**

虽然使用者通常不需要直接与 `loopbce.go` 代码交互，但理解其背后的原理可以帮助避免编写可能阻止 BCE 优化的代码。

一个常见的错误是 **在循环体内以非标准的方式修改归纳变量**。如果编译器无法识别清晰的归纳变量模式，就无法安全地消除边界检查。

**举例说明:**

```go
package main

func main() {
	arr := [10]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	for i := 0; i < len(arr); { // 注意这里没有 i++
		arr[i] = i * 2
		if i < 5 {
			i += 1
		} else {
			i += 2
		}
	}
	println(arr[5])
}
```

在这个例子中，虽然循环变量 `i` 最终会遍历整个数组，但其增量不是一个固定的常量。`findIndVar` 很可能无法识别 `i` 为一个标准的归纳变量，从而阻止 BCE 优化。编译器会保守地执行边界检查，因为无法静态地保证 `arr[i]` 的访问是安全的。

总而言之，`loopbce.go` 是 Go 编译器中一个重要的组成部分，它通过识别循环中的归纳变量，为循环边界检查消除这一关键优化提供了基础，从而提升 Go 程序的性能。理解其工作原理可以帮助开发者编写更易于编译器优化的代码。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/loopbce.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/types"
	"fmt"
)

type indVarFlags uint8

const (
	indVarMinExc    indVarFlags = 1 << iota // minimum value is exclusive (default: inclusive)
	indVarMaxInc                            // maximum value is inclusive (default: exclusive)
	indVarCountDown                         // if set the iteration starts at max and count towards min (default: min towards max)
)

type indVar struct {
	ind   *Value // induction variable
	nxt   *Value // the incremented variable
	min   *Value // minimum value, inclusive/exclusive depends on flags
	max   *Value // maximum value, inclusive/exclusive depends on flags
	entry *Block // entry block in the loop.
	flags indVarFlags
	// Invariant: for all blocks strictly dominated by entry:
	//	min <= ind <  max    [if flags == 0]
	//	min <  ind <  max    [if flags == indVarMinExc]
	//	min <= ind <= max    [if flags == indVarMaxInc]
	//	min <  ind <= max    [if flags == indVarMinExc|indVarMaxInc]
}

// parseIndVar checks whether the SSA value passed as argument is a valid induction
// variable, and, if so, extracts:
//   - the minimum bound
//   - the increment value
//   - the "next" value (SSA value that is Phi'd into the induction variable every loop)
//
// Currently, we detect induction variables that match (Phi min nxt),
// with nxt being (Add inc ind).
// If it can't parse the induction variable correctly, it returns (nil, nil, nil).
func parseIndVar(ind *Value) (min, inc, nxt *Value) {
	if ind.Op != OpPhi {
		return
	}

	if n := ind.Args[0]; (n.Op == OpAdd64 || n.Op == OpAdd32 || n.Op == OpAdd16 || n.Op == OpAdd8) && (n.Args[0] == ind || n.Args[1] == ind) {
		min, nxt = ind.Args[1], n
	} else if n := ind.Args[1]; (n.Op == OpAdd64 || n.Op == OpAdd32 || n.Op == OpAdd16 || n.Op == OpAdd8) && (n.Args[0] == ind || n.Args[1] == ind) {
		min, nxt = ind.Args[0], n
	} else {
		// Not a recognized induction variable.
		return
	}

	if nxt.Args[0] == ind { // nxt = ind + inc
		inc = nxt.Args[1]
	} else if nxt.Args[1] == ind { // nxt = inc + ind
		inc = nxt.Args[0]
	} else {
		panic("unreachable") // one of the cases must be true from the above.
	}

	return
}

// findIndVar finds induction variables in a function.
//
// Look for variables and blocks that satisfy the following
//
//	 loop:
//	   ind = (Phi min nxt),
//	   if ind < max
//	     then goto enter_loop
//	     else goto exit_loop
//
//	   enter_loop:
//		do something
//	      nxt = inc + ind
//		goto loop
//
//	 exit_loop:
func findIndVar(f *Func) []indVar {
	var iv []indVar
	sdom := f.Sdom()

	for _, b := range f.Blocks {
		if b.Kind != BlockIf || len(b.Preds) != 2 {
			continue
		}

		var ind *Value   // induction variable
		var init *Value  // starting value
		var limit *Value // ending value

		// Check that the control if it either ind </<= limit or limit </<= ind.
		// TODO: Handle unsigned comparisons?
		c := b.Controls[0]
		inclusive := false
		switch c.Op {
		case OpLeq64, OpLeq32, OpLeq16, OpLeq8:
			inclusive = true
			fallthrough
		case OpLess64, OpLess32, OpLess16, OpLess8:
			ind, limit = c.Args[0], c.Args[1]
		default:
			continue
		}

		// See if this is really an induction variable
		less := true
		init, inc, nxt := parseIndVar(ind)
		if init == nil {
			// We failed to parse the induction variable. Before punting, we want to check
			// whether the control op was written with the induction variable on the RHS
			// instead of the LHS. This happens for the downwards case, like:
			//     for i := len(n)-1; i >= 0; i--
			init, inc, nxt = parseIndVar(limit)
			if init == nil {
				// No recognized induction variable on either operand
				continue
			}

			// Ok, the arguments were reversed. Swap them, and remember that we're
			// looking at an ind >/>= loop (so the induction must be decrementing).
			ind, limit = limit, ind
			less = false
		}

		if ind.Block != b {
			// TODO: Could be extended to include disjointed loop headers.
			// I don't think this is causing missed optimizations in real world code often.
			// See https://go.dev/issue/63955
			continue
		}

		// Expect the increment to be a nonzero constant.
		if !inc.isGenericIntConst() {
			continue
		}
		step := inc.AuxInt
		if step == 0 {
			continue
		}

		// Increment sign must match comparison direction.
		// When incrementing, the termination comparison must be ind </<= limit.
		// When decrementing, the termination comparison must be ind >/>= limit.
		// See issue 26116.
		if step > 0 && !less {
			continue
		}
		if step < 0 && less {
			continue
		}

		// Up to now we extracted the induction variable (ind),
		// the increment delta (inc), the temporary sum (nxt),
		// the initial value (init) and the limiting value (limit).
		//
		// We also know that ind has the form (Phi init nxt) where
		// nxt is (Add inc nxt) which means: 1) inc dominates nxt
		// and 2) there is a loop starting at inc and containing nxt.
		//
		// We need to prove that the induction variable is incremented
		// only when it's smaller than the limiting value.
		// Two conditions must happen listed below to accept ind
		// as an induction variable.

		// First condition: loop entry has a single predecessor, which
		// is the header block.  This implies that b.Succs[0] is
		// reached iff ind < limit.
		if len(b.Succs[0].b.Preds) != 1 {
			// b.Succs[1] must exit the loop.
			continue
		}

		// Second condition: b.Succs[0] dominates nxt so that
		// nxt is computed when inc < limit.
		if !sdom.IsAncestorEq(b.Succs[0].b, nxt.Block) {
			// inc+ind can only be reached through the branch that enters the loop.
			continue
		}

		// Check for overflow/underflow. We need to make sure that inc never causes
		// the induction variable to wrap around.
		// We use a function wrapper here for easy return true / return false / keep going logic.
		// This function returns true if the increment will never overflow/underflow.
		ok := func() bool {
			if step > 0 {
				if limit.isGenericIntConst() {
					// Figure out the actual largest value.
					v := limit.AuxInt
					if !inclusive {
						if v == minSignedValue(limit.Type) {
							return false // < minint is never satisfiable.
						}
						v--
					}
					if init.isGenericIntConst() {
						// Use stride to compute a better lower limit.
						if init.AuxInt > v {
							return false
						}
						v = addU(init.AuxInt, diff(v, init.AuxInt)/uint64(step)*uint64(step))
					}
					if addWillOverflow(v, step) {
						return false
					}
					if inclusive && v != limit.AuxInt || !inclusive && v+1 != limit.AuxInt {
						// We know a better limit than the programmer did. Use our limit instead.
						limit = f.constVal(limit.Op, limit.Type, v, true)
						inclusive = true
					}
					return true
				}
				if step == 1 && !inclusive {
					// Can't overflow because maxint is never a possible value.
					return true
				}
				// If the limit is not a constant, check to see if it is a
				// negative offset from a known non-negative value.
				knn, k := findKNN(limit)
				if knn == nil || k < 0 {
					return false
				}
				// limit == (something nonnegative) - k. That subtraction can't underflow, so
				// we can trust it.
				if inclusive {
					// ind <= knn - k cannot overflow if step is at most k
					return step <= k
				}
				// ind < knn - k cannot overflow if step is at most k+1
				return step <= k+1 && k != maxSignedValue(limit.Type)
			} else { // step < 0
				if limit.Op == OpConst64 {
					// Figure out the actual smallest value.
					v := limit.AuxInt
					if !inclusive {
						if v == maxSignedValue(limit.Type) {
							return false // > maxint is never satisfiable.
						}
						v++
					}
					if init.isGenericIntConst() {
						// Use stride to compute a better lower limit.
						if init.AuxInt < v {
							return false
						}
						v = subU(init.AuxInt, diff(init.AuxInt, v)/uint64(-step)*uint64(-step))
					}
					if subWillUnderflow(v, -step) {
						return false
					}
					if inclusive && v != limit.AuxInt || !inclusive && v-1 != limit.AuxInt {
						// We know a better limit than the programmer did. Use our limit instead.
						limit = f.constVal(limit.Op, limit.Type, v, true)
						inclusive = true
					}
					return true
				}
				if step == -1 && !inclusive {
					// Can't underflow because minint is never a possible value.
					return true
				}
			}
			return false

		}

		if ok() {
			flags := indVarFlags(0)
			var min, max *Value
			if step > 0 {
				min = init
				max = limit
				if inclusive {
					flags |= indVarMaxInc
				}
			} else {
				min = limit
				max = init
				flags |= indVarMaxInc
				if !inclusive {
					flags |= indVarMinExc
				}
				flags |= indVarCountDown
				step = -step
			}
			if f.pass.debug >= 1 {
				printIndVar(b, ind, min, max, step, flags)
			}

			iv = append(iv, indVar{
				ind:   ind,
				nxt:   nxt,
				min:   min,
				max:   max,
				entry: b.Succs[0].b,
				flags: flags,
			})
			b.Logf("found induction variable %v (inc = %v, min = %v, max = %v)\n", ind, inc, min, max)
		}

		// TODO: other unrolling idioms
		// for i := 0; i < KNN - KNN % k ; i += k
		// for i := 0; i < KNN&^(k-1) ; i += k // k a power of 2
		// for i := 0; i < KNN&(-k) ; i += k // k a power of 2
	}

	return iv
}

// addWillOverflow reports whether x+y would result in a value more than maxint.
func addWillOverflow(x, y int64) bool {
	return x+y < x
}

// subWillUnderflow reports whether x-y would result in a value less than minint.
func subWillUnderflow(x, y int64) bool {
	return x-y > x
}

// diff returns x-y as a uint64. Requires x>=y.
func diff(x, y int64) uint64 {
	if x < y {
		base.Fatalf("diff %d - %d underflowed", x, y)
	}
	return uint64(x - y)
}

// addU returns x+y. Requires that x+y does not overflow an int64.
func addU(x int64, y uint64) int64 {
	if y >= 1<<63 {
		if x >= 0 {
			base.Fatalf("addU overflowed %d + %d", x, y)
		}
		x += 1<<63 - 1
		x += 1
		y -= 1 << 63
	}
	if addWillOverflow(x, int64(y)) {
		base.Fatalf("addU overflowed %d + %d", x, y)
	}
	return x + int64(y)
}

// subU returns x-y. Requires that x-y does not underflow an int64.
func subU(x int64, y uint64) int64 {
	if y >= 1<<63 {
		if x < 0 {
			base.Fatalf("subU underflowed %d - %d", x, y)
		}
		x -= 1<<63 - 1
		x -= 1
		y -= 1 << 63
	}
	if subWillUnderflow(x, int64(y)) {
		base.Fatalf("subU underflowed %d - %d", x, y)
	}
	return x - int64(y)
}

// if v is known to be x - c, where x is known to be nonnegative and c is a
// constant, return x, c. Otherwise return nil, 0.
func findKNN(v *Value) (*Value, int64) {
	var x, y *Value
	x = v
	switch v.Op {
	case OpSub64, OpSub32, OpSub16, OpSub8:
		x = v.Args[0]
		y = v.Args[1]

	case OpAdd64, OpAdd32, OpAdd16, OpAdd8:
		x = v.Args[0]
		y = v.Args[1]
		if x.isGenericIntConst() {
			x, y = y, x
		}
	}
	switch x.Op {
	case OpSliceLen, OpStringLen, OpSliceCap:
	default:
		return nil, 0
	}
	if y == nil {
		return x, 0
	}
	if !y.isGenericIntConst() {
		return nil, 0
	}
	if v.Op == OpAdd64 || v.Op == OpAdd32 || v.Op == OpAdd16 || v.Op == OpAdd8 {
		return x, -y.AuxInt
	}
	return x, y.AuxInt
}

func printIndVar(b *Block, i, min, max *Value, inc int64, flags indVarFlags) {
	mb1, mb2 := "[", "]"
	if flags&indVarMinExc != 0 {
		mb1 = "("
	}
	if flags&indVarMaxInc == 0 {
		mb2 = ")"
	}

	mlim1, mlim2 := fmt.Sprint(min.AuxInt), fmt.Sprint(max.AuxInt)
	if !min.isGenericIntConst() {
		if b.Func.pass.debug >= 2 {
			mlim1 = fmt.Sprint(min)
		} else {
			mlim1 = "?"
		}
	}
	if !max.isGenericIntConst() {
		if b.Func.pass.debug >= 2 {
			mlim2 = fmt.Sprint(max)
		} else {
			mlim2 = "?"
		}
	}
	extra := ""
	if b.Func.pass.debug >= 2 {
		extra = fmt.Sprintf(" (%s)", i)
	}
	b.Func.Warnl(b.Pos, "Induction variable: limits %v%v,%v%v, increment %d%s", mb1, mlim1, mlim2, mb2, inc, extra)
}

func minSignedValue(t *types.Type) int64 {
	return -1 << (t.Size()*8 - 1)
}

func maxSignedValue(t *types.Type) int64 {
	return 1<<((t.Size()*8)-1) - 1
}
```