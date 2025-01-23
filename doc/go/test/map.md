Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Scan and Context:** The file path `go/test/map.go` immediately suggests this is a *test* file for Go's map functionality. The comments at the beginning confirm this: "Test maps, almost exhaustively."  Knowing this drastically changes how we approach the code. It's not meant to be a practical example for users but rather a rigorous check of map behavior.

2. **Identify Key Functions:** The `main` function is the entry point, and it calls `testbasic()`, `testfloat()`, and `testnan()`. This suggests the code is organized into logical test groups.

3. **`testbasic()` Analysis:**

   * **Map Literals:**  The first thing it does is create a map literal `mlit`. This is a basic way to initialize a map with values. The code then iterates through it, verifying the values are correct. This is a basic correctness test.

   * **`make(map[...])`:** The code proceeds to create various maps with different key and value types using `make`. This indicates it's testing maps with various data types: `int`, `bool`, `float32`, `string`, slices (`[]string`), structs (`T`), pointers to structs (`*T`), and even maps as values (`map[int]int`). This highlights the versatility of Go maps.

   * **Population Loop:**  The `for` loop that follows populates these maps. The use of `strconv.Itoa` suggests it's using string conversions for some keys. The creation of struct `T` and pointer `apT` introduces more complex key/value scenarios.

   * **`len()` Checks:**  After populating, the code checks the `len()` of each map. This verifies that the correct number of elements was added.

   * **Direct Construction and Lookups:** The next `for` loop verifies the values in the maps are correct by directly accessing them using the key.

   * **Tuple/Comma-Ok Idiom:** The code extensively uses the "comma-ok idiom" (`value, ok := map[key]`). This is a crucial part of testing map behavior, specifically checking for the *existence* of keys. It tests both scenarios: existing keys returning `true` for `ok`, and non-existent keys returning `false`. The loop runs from `0` to `count` for existing keys and `count` to `2*count` for non-existent keys.

   * **Structured Element Updates:** The final part of `testbasic()` focuses on updating elements within maps where the values are themselves structured (slices and structs). This verifies that map elements can be modified in place.

   * **Range on Nil Map:**  The test `range on nil map` is a specific edge case test.

4. **`testfloat()` Analysis:**

   * **Floating-Point Specifics:** The comments clearly state the purpose: "Test floating point numbers in maps."  It focuses on the special behavior of floating-point numbers:
      * `+0` and `-0` should be treated as equal as keys.
      * `NaN` (Not a Number) should *not* be equal to itself, meaning you can have multiple `NaN` keys.

   * **Testing with `float32`, `float64`, `complex64`, `complex128`:** The code tests these properties across different floating-point types (including complex numbers).

5. **`testnan()` Analysis:**

   * **Further `NaN` Testing:** This function specifically tests inserting `NaN` values as keys multiple times and then iterating through the map to ensure the behavior is as expected (multiple `NaN` keys can exist).

6. **Inferring Go Language Feature:** Based on the code, the primary Go language feature being tested is obviously **maps**. The code demonstrates:

   * **Map Literal Initialization.**
   * **`make` for Map Creation.**
   * **Different Key and Value Types.**
   * **Accessing Map Elements.**
   * **Updating Map Elements.**
   * **Deleting Map Elements (implicitly through overwriting, not explicit `delete`).**
   * **Checking Key Existence (Comma-Ok Idiom).**
   * **`len()` function for Map Size.**
   * **`range` Loop for Iteration.**
   * **Special Handling of Floating-Point Keys (`+0`, `-0`, `NaN`).**

7. **Example Code:**  A simple example demonstrating map usage would be helpful.

8. **Code Logic Explanation:**  Walk through the `testbasic` function with a small `count` value (like 2) to make the flow easier to understand. This helps visualize the map creations, population, and lookups. Highlight the "comma-ok idiom" as a core concept.

9. **Command-Line Arguments:**  Scan the code for any usage of `os.Args` or similar. Since none are found, explicitly state that there are no command-line arguments handled.

10. **Common Mistakes:** Think about typical errors developers make when using maps. The most common is likely forgetting to check for key existence before accessing, which can lead to the default zero value. Another is the behavior of `NaN` as a key.

11. **Review and Refine:** Read through the entire analysis, ensuring clarity, accuracy, and completeness. Structure the information logically to address each part of the prompt. For instance, grouping the function analysis (`testbasic`, `testfloat`, `testnan`) together makes sense. Similarly, grouping the inferred feature and example code.

This systematic approach, starting from the high-level purpose and drilling down into the details of each function, combined with the knowledge that it's a *test* file, allows for a comprehensive and accurate understanding of the code's functionality.
好的，让我们来分析一下这段 Go 代码。

**功能归纳**

这段 Go 代码的主要功能是**详尽地测试 Go 语言中 `map` (映射) 数据结构的各种行为和特性**。它通过创建不同类型的 map，进行插入、读取、更新、删除（通过覆盖实现）、查询存在性等操作，并针对浮点数和 NaN 值的特殊情况进行了测试。代码的目标是验证 Go 语言 map 实现的正确性和健壮性。

**推理 Go 语言功能并举例说明**

这段代码的核心功能是测试 Go 语言的 **`map` 类型**。`map` 是一种无序的键值对集合，类似于其他语言中的字典或哈希表。

**Go 代码示例：**

```go
package main

import "fmt"

func main() {
	// 创建一个 string 到 int 的 map
	ages := make(map[string]int)

	// 添加键值对
	ages["Alice"] = 30
	ages["Bob"] = 25

	// 读取值
	fmt.Println("Alice 的年龄:", ages["Alice"]) // 输出: Alice 的年龄: 30

	// 检查键是否存在
	age, ok := ages["Charlie"]
	if ok {
		fmt.Println("Charlie 的年龄:", age)
	} else {
		fmt.Println("Charlie 的年龄未找到") // 输出: Charlie 的年龄未找到
	}

	// 更新值
	ages["Alice"] = 31
	fmt.Println("Alice 更新后的年龄:", ages["Alice"]) // 输出: Alice 更新后的年龄: 31

	// 删除键值对 (Go 中没有直接的删除，通常通过赋予零值或者使用其他逻辑处理)
	ages["Bob"] = 0 // 假设 0 代表删除或无效
	fmt.Println("Bob 的年龄:", ages["Bob"])       // 输出: Bob 的年龄: 0

	// 获取 map 的长度
	fmt.Println("Map 的长度:", len(ages)) // 输出: Map 的长度: 2

	// 使用 for...range 遍历 map
	for name, age := range ages {
		fmt.Printf("%s 的年龄是 %d\n", name, age)
	}
	// 输出 (顺序可能不同):
	// Alice 的年龄是 31
	// Bob 的年龄是 0
}
```

**代码逻辑介绍 (带假设的输入与输出)**

我们以 `testbasic()` 函数为例进行介绍，并假设 `count = 2`。

**假设输入:**  `count` 常量被设置为 `2`。

**代码执行流程 (简化):**

1. **`mlit` 测试:** 创建一个 map 字面量 `mlit := map[string]int{"0": 0, "1": 1}`。循环两次，检查 `mlit["0"]` 是否等于 `0`，`mlit["1"]` 是否等于 `1`。如果不是，则 `panic`。

2. **创建各种类型的 map:**
   - `mib`: `map[int]bool`
   - `mii`: `map[int]int`
   - ... 以及其他多种类型的 map。

3. **填充 map (循环 `i` 从 0 到 1):**
   - 当 `i = 0`:
     - `s = "0"`, `s10 = "0"`
     - `f = 0.0`
     - 创建结构体 `t = {0, 0.0}`
     - 创建指向结构体的指针 `apT[0]` 和 `apT[2]`，并赋值
     - `mib[0] = false`
     - `mii[0] = 0`
     - `mfi[0.0] = 0`
     - `mif[0] = 0.0`
     - `mis[0] = "0"`
     - `msi["0"] = 0`
     - `mss["0"] = "0"`
     - `mspa["0"] = ["0", "0"]`
     - `mipT[0]` 指向 `apT[0]`
     - `mpTi[apT[0]] = 0`
     - `mipM[0] = {0: 1}`
     - `mit[0] = {0, 0.0}`
   - 当 `i = 1`:
     - `s = "1"`, `s10 = "10"`
     - `f = 1.0`
     - 创建结构体 `t = {1, 1.0}`
     - 创建指向结构体的指针 `apT[1]` 和 `apT[3]`，并赋值
     - `mib[1] = true`
     - `mii[1] = 10`
     - `mfi[1.0] = 10`
     - `mif[1] = 10.0`
     - `mis[1] = "1"`
     - `msi["1"] = 1`
     - `mss["1"] = "10"`
     - `mspa["1"] = ["10", "10"]`
     - `mipT[1]` 指向 `apT[1]`
     - `mpTi[apT[1]] = 1`
     - `mipM[1] = {1: 2}`
     - `mit[1] = {1, 1.0}`

4. **测试 `len`:** 检查所有 map 的长度是否为 `count` (即 2)。

5. **直接构造测试:** 再次循环 `i` 从 0 到 1，直接访问 map 的元素，并验证其值是否正确。例如，检查 `mib[0]` 是否为 `false`，`mii[1]` 是否为 `10`，等等。

6. **测试存在性 (Tuple Check):**
   - 循环 `i` 从 0 到 1：使用 `_, b := mib[i]` 的形式检查键是否存在，并验证 `b` 的值是否正确。

7. **测试不存在性 (Tuple Check):**
   - 循环 `i` 从 2 到 3 (因为 `count = 2`): 检查之前未插入的键是否存在，并验证 `b` 的值是否为 `false`。

8. **结构化 map 元素更新:**
   - 循环 `i` 从 0 到 1：修改 map 中值是结构体的元素。例如，修改 `mspa["0"][0]` 的值为 `"deleted"`，增加 `mipT[0].i` 的值，等等。

**假设输出 (如果所有测试都通过):** 代码不会产生任何输出到标准输出。如果任何断言失败，会触发 `panic` 并打印错误信息。

**命令行参数处理**

这段代码**没有处理任何命令行参数**。它是一个纯粹的单元测试文件，通过 `go test` 命令运行，不需要额外的命令行输入。

**使用者易犯错的点**

这段代码本身是测试代码，使用者通常不会直接修改或使用它。然而，基于它测试的内容，我们可以总结出使用 Go 语言 `map` 时容易犯错的点：

1. **未检查键是否存在就直接访问:**  如果尝试访问一个不存在的键，`map` 会返回该值类型的零值，这可能导致意想不到的结果。应该使用 "comma ok" 惯用法来检查键是否存在：

   ```go
   value, ok := myMap["nonexistent_key"]
   if ok {
       // 键存在，可以使用 value
   } else {
       // 键不存在
   }
   ```

2. **在并发环境下使用 `map` 而不加锁:**  Go 的 `map` 不是并发安全的。在多个 goroutine 中同时读写同一个 `map` 可能导致数据竞争和程序崩溃。需要使用 `sync.Mutex` 或 `sync.RWMutex` 等同步机制来保护 `map` 的访问。

3. **将 `map` 的零值 (nil map) 用于写操作:**  声明一个 `map` 但未用 `make` 初始化时，它的值是 `nil`。对 `nil map` 进行写操作会触发 panic。

   ```go
   var myMap map[string]int // myMap 是 nil
   // myMap["key"] = 1 // 运行时 panic: assignment to entry in nil map
   myMap = make(map[string]int) // 需要先用 make 初始化
   myMap["key"] = 1
   ```

4. **误解 `NaN` 作为 `map` 键的行为:**  在浮点数 `map` 中，`NaN` (Not a Number) 被认为不等于自身。因此，你可以将多个 `NaN` 值作为不同的键插入到 `map` 中。

   ```go
   import "math"
   import "fmt"

   func main() {
       m := make(map[float64]int)
       nan1 := math.NaN()
       nan2 := math.NaN()
       m[nan1] = 1
       m[nan2] = 2
       fmt.Println(len(m)) // 输出: 2
   }
   ```

5. **在迭代 `map` 时进行删除操作:**  在 `for...range` 循环中删除 `map` 的元素可能会导致迭代跳过某些元素或产生其他不可预测的行为。如果需要在迭代时删除元素，通常需要创建一个新的 `map` 或者使用其他策略。

希望以上分析能够帮助你理解这段 Go 代码的功能和相关的 Go 语言特性。

### 提示词
```
这是路径为go/test/map.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// run

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test maps, almost exhaustively.
// Complexity (linearity) test is in maplinear.go.

package main

import (
	"fmt"
	"math"
	"strconv"
)

const count = 100

func P(a []string) string {
	s := "{"
	for i := 0; i < len(a); i++ {
		if i > 0 {
			s += ","
		}
		s += `"` + a[i] + `"`
	}
	s += "}"
	return s
}

func main() {
	testbasic()
	testfloat()
	testnan()
}

func testbasic() {
	// Test a map literal.
	mlit := map[string]int{"0": 0, "1": 1, "2": 2, "3": 3, "4": 4}
	for i := 0; i < len(mlit); i++ {
		s := string([]byte{byte(i) + '0'})
		if mlit[s] != i {
			panic(fmt.Sprintf("mlit[%s] = %d\n", s, mlit[s]))
		}
	}

	mib := make(map[int]bool)
	mii := make(map[int]int)
	mfi := make(map[float32]int)
	mif := make(map[int]float32)
	msi := make(map[string]int)
	mis := make(map[int]string)
	mss := make(map[string]string)
	mspa := make(map[string][]string)
	// BUG need an interface map both ways too

	type T struct {
		i int64 // can't use string here; struct values are only compared at the top level
		f float32
	}
	mipT := make(map[int]*T)
	mpTi := make(map[*T]int)
	mit := make(map[int]T)
	//	mti := make(map[T] int)

	type M map[int]int
	mipM := make(map[int]M)

	var apT [2 * count]*T

	for i := 0; i < count; i++ {
		s := strconv.Itoa(i)
		s10 := strconv.Itoa(i * 10)
		f := float32(i)
		t := T{int64(i), f}
		apT[i] = new(T)
		apT[i].i = int64(i)
		apT[i].f = f
		apT[2*i] = new(T) // need twice as many entries as we use, for the nonexistence check
		apT[2*i].i = int64(i)
		apT[2*i].f = f
		m := M{i: i + 1}
		mib[i] = (i != 0)
		mii[i] = 10 * i
		mfi[float32(i)] = 10 * i
		mif[i] = 10.0 * f
		mis[i] = s
		msi[s] = i
		mss[s] = s10
		mss[s] = s10
		as := make([]string, 2)
		as[0] = s10
		as[1] = s10
		mspa[s] = as
		mipT[i] = apT[i]
		mpTi[apT[i]] = i
		mipM[i] = m
		mit[i] = t
		//	mti[t] = i
	}

	// test len
	if len(mib) != count {
		panic(fmt.Sprintf("len(mib) = %d\n", len(mib)))
	}
	if len(mii) != count {
		panic(fmt.Sprintf("len(mii) = %d\n", len(mii)))
	}
	if len(mfi) != count {
		panic(fmt.Sprintf("len(mfi) = %d\n", len(mfi)))
	}
	if len(mif) != count {
		panic(fmt.Sprintf("len(mif) = %d\n", len(mif)))
	}
	if len(msi) != count {
		panic(fmt.Sprintf("len(msi) = %d\n", len(msi)))
	}
	if len(mis) != count {
		panic(fmt.Sprintf("len(mis) = %d\n", len(mis)))
	}
	if len(mss) != count {
		panic(fmt.Sprintf("len(mss) = %d\n", len(mss)))
	}
	if len(mspa) != count {
		panic(fmt.Sprintf("len(mspa) = %d\n", len(mspa)))
	}
	if len(mipT) != count {
		panic(fmt.Sprintf("len(mipT) = %d\n", len(mipT)))
	}
	if len(mpTi) != count {
		panic(fmt.Sprintf("len(mpTi) = %d\n", len(mpTi)))
	}
	//	if len(mti) != count {
	//              panic(fmt.Sprintf("len(mti) = %d\n", len(mti)))
	//	}
	if len(mipM) != count {
		panic(fmt.Sprintf("len(mipM) = %d\n", len(mipM)))
	}
	//	if len(mti) != count {
	//		panic(fmt.Sprintf("len(mti) = %d\n", len(mti)))
	//	}
	if len(mit) != count {
		panic(fmt.Sprintf("len(mit) = %d\n", len(mit)))
	}

	// test construction directly
	for i := 0; i < count; i++ {
		s := strconv.Itoa(i)
		s10 := strconv.Itoa(i * 10)
		f := float32(i)
		// BUG m := M(i, i+1)
		if mib[i] != (i != 0) {
			panic(fmt.Sprintf("mib[%d] = %t\n", i, mib[i]))
		}
		if mii[i] != 10*i {
			panic(fmt.Sprintf("mii[%d] = %d\n", i, mii[i]))
		}
		if mfi[f] != 10*i {
			panic(fmt.Sprintf("mfi[%d] = %d\n", i, mfi[f]))
		}
		if mif[i] != 10.0*f {
			panic(fmt.Sprintf("mif[%d] = %g\n", i, mif[i]))
		}
		if mis[i] != s {
			panic(fmt.Sprintf("mis[%d] = %s\n", i, mis[i]))
		}
		if msi[s] != i {
			panic(fmt.Sprintf("msi[%s] = %d\n", s, msi[s]))
		}
		if mss[s] != s10 {
			panic(fmt.Sprintf("mss[%s] = %g\n", s, mss[s]))
		}
		for j := 0; j < len(mspa[s]); j++ {
			if mspa[s][j] != s10 {
				panic(fmt.Sprintf("mspa[%s][%d] = %s\n", s, j, mspa[s][j]))
			}
		}
		if mipT[i].i != int64(i) || mipT[i].f != f {
			panic(fmt.Sprintf("mipT[%d] = %v\n", i, mipT[i]))
		}
		if mpTi[apT[i]] != i {
			panic(fmt.Sprintf("mpTi[apT[%d]] = %d\n", i, mpTi[apT[i]]))
		}
		//	if(mti[t] != i) {
		//		panic(fmt.Sprintf("mti[%s] = %s\n", s, mti[t]))
		//	}
		if mipM[i][i] != i+1 {
			panic(fmt.Sprintf("mipM[%d][%d] = %d\n", i, i, mipM[i][i]))
		}
		//	if(mti[t] != i) {
		//		panic(fmt.Sprintf("mti[%v] = %d\n", t, mti[t]))
		//	}
		if mit[i].i != int64(i) || mit[i].f != f {
			panic(fmt.Sprintf("mit[%d] = {%d %g}\n", i, mit[i].i, mit[i].f))
		}
	}

	// test existence with tuple check
	// failed lookups yield a false value for the boolean.
	for i := 0; i < count; i++ {
		s := strconv.Itoa(i)
		f := float32(i)
		{
			_, b := mib[i]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mib[%d]\n", i))
			}
			_, b = mib[i]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mib[%d]\n", i))
			}
		}
		{
			_, b := mii[i]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mii[%d]\n", i))
			}
			_, b = mii[i]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mii[%d]\n", i))
			}
		}
		{
			_, b := mfi[f]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mfi[%d]\n", i))
			}
			_, b = mfi[f]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mfi[%d]\n", i))
			}
		}
		{
			_, b := mif[i]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mif[%d]\n", i))
			}
			_, b = mif[i]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mif[%d]\n", i))
			}
		}
		{
			_, b := mis[i]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mis[%d]\n", i))
			}
			_, b = mis[i]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mis[%d]\n", i))
			}
		}
		{
			_, b := msi[s]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: msi[%d]\n", i))
			}
			_, b = msi[s]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: msi[%d]\n", i))
			}
		}
		{
			_, b := mss[s]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mss[%d]\n", i))
			}
			_, b = mss[s]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mss[%d]\n", i))
			}
		}
		{
			_, b := mspa[s]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mspa[%d]\n", i))
			}
			_, b = mspa[s]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mspa[%d]\n", i))
			}
		}
		{
			_, b := mipT[i]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mipT[%d]\n", i))
			}
			_, b = mipT[i]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mipT[%d]\n", i))
			}
		}
		{
			_, b := mpTi[apT[i]]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mpTi[apT[%d]]\n", i))
			}
			_, b = mpTi[apT[i]]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mpTi[apT[%d]]\n", i))
			}
		}
		{
			_, b := mipM[i]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mipM[%d]\n", i))
			}
			_, b = mipM[i]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mipM[%d]\n", i))
			}
		}
		{
			_, b := mit[i]
			if !b {
				panic(fmt.Sprintf("tuple existence decl: mit[%d]\n", i))
			}
			_, b = mit[i]
			if !b {
				panic(fmt.Sprintf("tuple existence assign: mit[%d]\n", i))
			}
		}
		//		{
		//			_, b := mti[t]
		//			if !b {
		//				panic(fmt.Sprintf("tuple existence decl: mti[%d]\n", i))
		//			}
		//			_, b = mti[t]
		//			if !b {
		//				panic(fmt.Sprintf("tuple existence assign: mti[%d]\n", i))
		//			}
		//		}
	}

	// test nonexistence with tuple check
	// failed lookups yield a false value for the boolean.
	for i := count; i < 2*count; i++ {
		s := strconv.Itoa(i)
		f := float32(i)
		{
			_, b := mib[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mib[%d]", i))
			}
			_, b = mib[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mib[%d]", i))
			}
		}
		{
			_, b := mii[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mii[%d]", i))
			}
			_, b = mii[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mii[%d]", i))
			}
		}
		{
			_, b := mfi[f]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mfi[%d]", i))
			}
			_, b = mfi[f]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mfi[%d]", i))
			}
		}
		{
			_, b := mif[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mif[%d]", i))
			}
			_, b = mif[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mif[%d]", i))
			}
		}
		{
			_, b := mis[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mis[%d]", i))
			}
			_, b = mis[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mis[%d]", i))
			}
		}
		{
			_, b := msi[s]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: msi[%d]", i))
			}
			_, b = msi[s]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: msi[%d]", i))
			}
		}
		{
			_, b := mss[s]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mss[%d]", i))
			}
			_, b = mss[s]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mss[%d]", i))
			}
		}
		{
			_, b := mspa[s]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mspa[%d]", i))
			}
			_, b = mspa[s]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mspa[%d]", i))
			}
		}
		{
			_, b := mipT[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mipT[%d]", i))
			}
			_, b = mipT[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mipT[%d]", i))
			}
		}
		{
			_, b := mpTi[apT[i]]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mpTi[apt[%d]]", i))
			}
			_, b = mpTi[apT[i]]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mpTi[apT[%d]]", i))
			}
		}
		{
			_, b := mipM[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mipM[%d]", i))
			}
			_, b = mipM[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mipM[%d]", i))
			}
		}
		//		{
		//			_, b := mti[t]
		//			if b {
		//				panic(fmt.Sprintf("tuple nonexistence decl: mti[%d]", i))
		//			}
		//			_, b = mti[t]
		//			if b {
		//				panic(fmt.Sprintf("tuple nonexistence assign: mti[%d]", i))
		//			}
		//		}
		{
			_, b := mit[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence decl: mit[%d]", i))
			}
			_, b = mit[i]
			if b {
				panic(fmt.Sprintf("tuple nonexistence assign: mit[%d]", i))
			}
		}
	}

	// tests for structured map element updates
	for i := 0; i < count; i++ {
		s := strconv.Itoa(i)
		mspa[s][i%2] = "deleted"
		if mspa[s][i%2] != "deleted" {
			panic(fmt.Sprintf("update mspa[%s][%d] = %s\n", s, i%2, mspa[s][i%2]))

		}

		mipT[i].i += 1
		if mipT[i].i != int64(i)+1 {
			panic(fmt.Sprintf("update mipT[%d].i = %d\n", i, mipT[i].i))

		}
		mipT[i].f = float32(i + 1)
		if mipT[i].f != float32(i+1) {
			panic(fmt.Sprintf("update mipT[%d].f = %g\n", i, mipT[i].f))

		}

		mipM[i][i]++
		if mipM[i][i] != (i+1)+1 {
			panic(fmt.Sprintf("update mipM[%d][%d] = %d\n", i, i, mipM[i][i]))

		}
	}

	// test range on nil map
	var mnil map[string]int
	for _, _ = range mnil {
		panic("range mnil")
	}
}

func testfloat() {
	// Test floating point numbers in maps.
	// Two map keys refer to the same entry if the keys are ==.
	// The special cases, then, are that +0 == -0 and that NaN != NaN.

	{
		var (
			pz   = float32(0)
			nz   = math.Float32frombits(1 << 31)
			nana = float32(math.NaN())
			nanb = math.Float32frombits(math.Float32bits(nana) ^ 2)
		)

		m := map[float32]string{
			pz:   "+0",
			nana: "NaN",
			nanb: "NaN",
		}
		if m[pz] != "+0" {
			panic(fmt.Sprintln("float32 map cannot read back m[+0]:", m[pz]))
		}
		if m[nz] != "+0" {
			fmt.Sprintln("float32 map does not treat", pz, "and", nz, "as equal for read")
			panic(fmt.Sprintln("float32 map does not treat -0 and +0 as equal for read"))
		}
		m[nz] = "-0"
		if m[pz] != "-0" {
			panic(fmt.Sprintln("float32 map does not treat -0 and +0 as equal for write"))
		}
		if _, ok := m[nana]; ok {
			panic(fmt.Sprintln("float32 map allows NaN lookup (a)"))
		}
		if _, ok := m[nanb]; ok {
			panic(fmt.Sprintln("float32 map allows NaN lookup (b)"))
		}
		if len(m) != 3 {
			panic(fmt.Sprintln("float32 map should have 3 entries:", m))
		}
		m[nana] = "NaN"
		m[nanb] = "NaN"
		if len(m) != 5 {
			panic(fmt.Sprintln("float32 map should have 5 entries:", m))
		}
	}

	{
		var (
			pz   = float64(0)
			nz   = math.Float64frombits(1 << 63)
			nana = float64(math.NaN())
			nanb = math.Float64frombits(math.Float64bits(nana) ^ 2)
		)

		m := map[float64]string{
			pz:   "+0",
			nana: "NaN",
			nanb: "NaN",
		}
		if m[nz] != "+0" {
			panic(fmt.Sprintln("float64 map does not treat -0 and +0 as equal for read"))
		}
		m[nz] = "-0"
		if m[pz] != "-0" {
			panic(fmt.Sprintln("float64 map does not treat -0 and +0 as equal for write"))
		}
		if _, ok := m[nana]; ok {
			panic(fmt.Sprintln("float64 map allows NaN lookup (a)"))
		}
		if _, ok := m[nanb]; ok {
			panic(fmt.Sprintln("float64 map allows NaN lookup (b)"))
		}
		if len(m) != 3 {
			panic(fmt.Sprintln("float64 map should have 3 entries:", m))
		}
		m[nana] = "NaN"
		m[nanb] = "NaN"
		if len(m) != 5 {
			panic(fmt.Sprintln("float64 map should have 5 entries:", m))
		}
	}

	{
		var (
			pz   = complex64(0)
			nz   = complex(0, math.Float32frombits(1<<31))
			nana = complex(5, float32(math.NaN()))
			nanb = complex(5, math.Float32frombits(math.Float32bits(float32(math.NaN()))^2))
		)

		m := map[complex64]string{
			pz:   "+0",
			nana: "NaN",
			nanb: "NaN",
		}
		if m[nz] != "+0" {
			panic(fmt.Sprintln("complex64 map does not treat -0 and +0 as equal for read"))
		}
		m[nz] = "-0"
		if m[pz] != "-0" {
			panic(fmt.Sprintln("complex64 map does not treat -0 and +0 as equal for write"))
		}
		if _, ok := m[nana]; ok {
			panic(fmt.Sprintln("complex64 map allows NaN lookup (a)"))
		}
		if _, ok := m[nanb]; ok {
			panic(fmt.Sprintln("complex64 map allows NaN lookup (b)"))
		}
		if len(m) != 3 {
			panic(fmt.Sprintln("complex64 map should have 3 entries:", m))
		}
		m[nana] = "NaN"
		m[nanb] = "NaN"
		if len(m) != 5 {
			panic(fmt.Sprintln("complex64 map should have 5 entries:", m))
		}
	}

	{
		var (
			pz   = complex128(0)
			nz   = complex(0, math.Float64frombits(1<<63))
			nana = complex(5, float64(math.NaN()))
			nanb = complex(5, math.Float64frombits(math.Float64bits(float64(math.NaN()))^2))
		)

		m := map[complex128]string{
			pz:   "+0",
			nana: "NaN",
			nanb: "NaN",
		}
		if m[nz] != "+0" {
			panic(fmt.Sprintln("complex128 map does not treat -0 and +0 as equal for read"))
		}
		m[nz] = "-0"
		if m[pz] != "-0" {
			panic(fmt.Sprintln("complex128 map does not treat -0 and +0 as equal for write"))
		}
		if _, ok := m[nana]; ok {
			panic(fmt.Sprintln("complex128 map allows NaN lookup (a)"))
		}
		if _, ok := m[nanb]; ok {
			panic(fmt.Sprintln("complex128 map allows NaN lookup (b)"))
		}
		if len(m) != 3 {
			panic(fmt.Sprintln("complex128 map should have 3 entries:", m))
		}
		m[nana] = "NaN"
		m[nanb] = "NaN"
		if len(m) != 5 {
			panic(fmt.Sprintln("complex128 map should have 5 entries:", m))
		}
	}
}

func testnan() {
	n := 500
	m := map[float64]int{}
	nan := math.NaN()
	for i := 0; i < n; i++ {
		m[nan] = 1
	}
	if len(m) != n {
		panic("wrong size map after nan insertion")
	}
	iters := 0
	for k, v := range m {
		iters++
		if !math.IsNaN(k) {
			panic("not NaN")
		}
		if v != 1 {
			panic("wrong value")
		}
	}
	if iters != n {
		panic("wrong number of nan range iters")
	}
}
```