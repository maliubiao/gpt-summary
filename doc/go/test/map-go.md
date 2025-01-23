Response: The user wants to understand the functionality of the provided Go code snippet. The code seems to be a test suite for Go's map feature.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the purpose:** The comment `// Test maps, almost exhaustively.` at the beginning clearly indicates that this code is designed to test the functionality of Go maps. The filename `map.go` in the `go/test` directory further reinforces this.

2. **Examine the `main` function:** The `main` function calls `testbasic()` and `testfloat()`. This suggests that the tests are organized into different categories. A quick look at the function names provides hints about what is being tested.

3. **Analyze `testbasic()`:**
    * **Map Literals:** The code initializes a map using a literal `mlit := map[string]int{"0": 0, ...}` and verifies its contents. This tests the basic syntax and functionality of map literals.
    * **Map Creation with `make`:** The code uses `make(map[type]type)` to create various maps with different key-value types (int, bool, float32, string, struct, map). This suggests testing map creation with different data types.
    * **Basic Operations:** The code then populates these maps with data and performs checks using `len()`, direct access (`m[key]`), and the "comma ok" idiom for checking key existence. This tests core map functionalities.
    * **Structured Element Updates:** The code demonstrates updating elements within a map where the value is a slice or a struct. This tests the mutability of map values.
    * **Range on Nil Map:** The code tests that iterating over a nil map does not cause a panic.

4. **Analyze `testfloat()`:**
    * **Floating-Point Key Behavior:** This function focuses on testing how floating-point numbers are handled as map keys. It specifically addresses the cases of `+0` and `-0` being treated as equal and `NaN` not being equal to itself. It tests both `float32` and `float64` maps, as well as maps with `complex64` and `complex128` keys.

5. **Analyze `testnan()`:**
    * **NaN as Key:** This function specifically tests using `NaN` as a key in a map. It confirms that multiple insertions of `NaN` keys result in multiple distinct entries and that iterating over the map yields `NaN` keys.

6. **Infer Go Language Features:** Based on the tests, the code demonstrates the following Go map features:
    * Map literals
    * Creating maps using `make`
    * Different key and value types
    * Getting the length of a map using `len()`
    * Accessing map values using `m[key]`
    * Checking key existence using the "comma ok" idiom (`value, ok := m[key]`)
    * Updating map values
    * Iterating over maps using `range`
    * Handling floating-point keys, including `+0`, `-0`, and `NaN`

7. **Provide Code Examples:** Based on the analysis, create simple Go code examples to illustrate the identified features.

8. **Address Potential Errors:**  Consider common mistakes developers might make when using maps, such as:
    * Assuming a specific iteration order (maps are unordered).
    * Modifying a map while iterating over it.
    * Using non-comparable types as keys.
    * Not checking for key existence before accessing a value.

9. **Review and Refine:** Ensure the explanation is clear, concise, and accurately reflects the functionality of the provided code. Double-check the code examples and error scenarios. For example, initially, I didn't explicitly mention the unordered nature of maps, but that's a crucial point and a common source of confusion. So I added that to the "易犯错的点".
这段Go语言代码实现了一个针对Go语言中 `map` (映射/字典) 功能的详尽测试套件。它涵盖了 `map` 的多种使用场景和边界情况。

以下是它的主要功能：

1. **基本 Map 操作测试 (`testbasic`)**:
    *   **Map 字面量 (Map Literals)**: 测试使用字面量创建并初始化 `map`。
    *   **不同类型的键和值**: 测试使用各种基本类型（如 `int`, `bool`, `float32`, `string`）以及结构体、`map` 本身作为键或值。
    *   **`len()` 函数**: 验证使用 `len()` 函数获取 `map` 中元素数量的正确性。
    *   **元素访问**: 测试通过键访问 `map` 中元素的值。
    *   **存在性检查 (Comma-ok idiom)**: 测试使用 `value, ok := m[key]` 语法来检查键是否存在于 `map` 中。
    *   **元素更新**: 测试修改 `map` 中已存在键的值。
    *   **结构化元素的更新**: 测试当 `map` 的值是结构体或切片时，更新其内部字段或元素的行为。
    *   **在 `nil` Map 上进行 `range` 迭代**:  验证在 `nil` 的 `map` 上进行 `range` 循环不会导致 panic。

2. **浮点数键测试 (`testfloat`)**:
    *   **`+0` 和 `-0`**: 测试 `map` 如何处理浮点数键中的正零 (`+0`) 和负零 (`-0`)，验证它们是否被认为是相等的键。
    *   **`NaN` (Not a Number)**: 测试 `map` 如何处理 `NaN` 作为键，验证 `NaN` 不等于自身，因此作为键插入时会被视为不同的条目。该测试覆盖了 `float32`, `float64`, `complex64`, `complex128` 等浮点数类型。

3. **`NaN` 键的详细测试 (`testnan`)**:
    *   更深入地测试将 `NaN` 作为键插入 `map` 的行为，验证多次插入 `NaN` 会产生多个不同的键值对，并且在 `range` 迭代时能正确遍历这些 `NaN` 键。

**它可以被推理为 Go 语言 `map` 功能的单元测试。** 开发者可以使用这个文件来验证 Go 语言的 `map` 实现是否符合预期，以及在各种场景下是否能正确工作。

**Go 代码示例说明：**

**1. 基本 Map 操作:**

```go
package main

import "fmt"

func main() {
	// 创建一个 string 到 int 的 map
	ages := make(map[string]int)

	// 添加元素
	ages["Alice"] = 30
	ages["Bob"] = 25

	// 访问元素
	fmt.Println("Alice's age:", ages["Alice"]) // 输出: Alice's age: 30

	// 检查键是否存在
	age, ok := ages["Charlie"]
	if ok {
		fmt.Println("Charlie's age:", age)
	} else {
		fmt.Println("Charlie's age not found") // 输出: Charlie's age not found
	}

	// 获取 map 的长度
	fmt.Println("Number of entries:", len(ages)) // 输出: Number of entries: 2

	// 更新元素
	ages["Alice"] = 31
	fmt.Println("Updated Alice's age:", ages["Alice"]) // 输出: Updated Alice's age: 31

	// 删除元素
	delete(ages, "Bob")
	fmt.Println("Number of entries after deletion:", len(ages)) // 输出: Number of entries after deletion: 1

	// 使用字面量创建 map
	scores := map[string]int{"John": 90, "Jane": 85}
	fmt.Println("Scores:", scores) // 输出: Scores: map[Jane:85 John:90]

	// 遍历 map
	for name, score := range scores {
		fmt.Printf("%s's score: %d\n", name, score)
	}
}
```

**假设的输入与输出:**

上面的代码示例中没有外部输入，它的输出是固定的，已经在注释中给出。

**2. 浮点数键的 Map:**

```go
package main

import (
	"fmt"
	"math"
)

func main() {
	// 测试 +0 和 -0
	floatMap := make(map[float64]string)
	plusZero := 0.0
	minusZero := math.Copysign(0.0, -1.0)

	floatMap[plusZero] = "positive zero"
	fmt.Println(floatMap[minusZero]) // 输出: positive zero (因为 +0 和 -0 被认为是相等的键)

	// 测试 NaN
	nanMap := make(map[float64]int)
	nan1 := math.NaN()
	nan2 := math.NaN()

	nanMap[nan1] = 1
	nanMap[nan2] = 2 // NaN 不等于自身，会被视为不同的键

	fmt.Println("Length of nanMap:", len(nanMap)) // 输出: Length of nanMap: 2

	// 遍历包含 NaN 键的 map
	for key, value := range nanMap {
		fmt.Printf("Key: %f, Value: %d, IsNaN: %t\n", key, value, math.IsNaN(key))
		// 可能输出:
		// Key: NaN, Value: 1, IsNaN: true
		// Key: NaN, Value: 2, IsNaN: true
	}
}
```

**假设的输入与输出:**

这个示例也没有外部输入，输出也在注释中给出。需要注意的是，`NaN` 的具体表示可能因平台而异，但 `math.IsNaN()` 可以正确识别。

**命令行参数的具体处理：**

这段代码本身是一个测试文件，不涉及命令行参数的处理。它通常通过 Go 的测试工具链 (`go test`) 运行。

**使用者易犯错的点：**

1. **假设 Map 的迭代顺序:** Go 的 `map` 在进行 `range` 迭代时，元素的顺序是**不确定**的。依赖固定的迭代顺序是错误的。

    ```go
    package main

    import "fmt"

    func main() {
        m := map[string]int{"a": 1, "b": 2, "c": 3}
        for key, value := range m {
            fmt.Println(key, value)
        }
        // 输出顺序是不确定的，每次运行可能不同
    }
    ```

2. **并发访问 Map 而没有适当的同步:**  在多个 Goroutine 中并发地读写同一个 `map` 是不安全的，会导致数据竞争。需要使用互斥锁（`sync.Mutex`）或其他同步机制来保护 `map` 的并发访问。

    ```go
    package main

    import (
        "fmt"
        "sync"
        "time"
    )

    func main() {
        m := make(map[int]int)
        var wg sync.WaitGroup
        var mu sync.Mutex

        for i := 0; i < 100; i++ {
            wg.Add(2)
            go func(key int) {
                defer wg.Done()
                mu.Lock()
                m[key] = key * 2
                mu.Unlock()
            }(i)
            go func(key int) {
                defer wg.Done()
                mu.Lock()
                _, ok := m[key]
                mu.Unlock()
                if ok {
                    // do something
                }
            }(i)
        }
        wg.Wait()
        fmt.Println("Map operations completed")
    }
    ```

3. **使用不可比较的类型作为 Map 的键:**  Go 的 `map` 的键必须是可比较的类型。切片 (`[]T`)、`map` 类型本身以及包含不可比较字段的结构体不能直接作为 `map` 的键。

    ```go
    package main

    func main() {
        // 编译错误：invalid map key type []int
        // m := make(map[[]int]string)

        // 编译错误：invalid map key type map[string]int
        // m := make(map[map[string]int]string)

        type NotComparable struct {
            s []int
        }
        // 编译错误：invalid map key type main.NotComparable
        // m := make(map[NotComparable]string)
    }
    ```

4. **尝试访问不存在的键而不进行检查:** 直接访问 `map` 中不存在的键会返回该值类型的零值，但这可能不是预期的行为。使用 "comma-ok" 惯用法可以更安全地处理这种情况。

    ```go
    package main

    import "fmt"

    func main() {
        ages := map[string]int{"Alice": 30}
        age := ages["Bob"] // age 将会是 int 的零值 0
        fmt.Println("Bob's age:", age)

        age, ok := ages["Bob"]
        if ok {
            fmt.Println("Bob's age:", age)
        } else {
            fmt.Println("Bob's age not found")
        }
    }
    ```

这段测试代码通过各种场景的验证，确保了 Go 语言 `map` 功能的稳定性和正确性。 开发者可以参考这些测试用例来理解 `map` 的行为和使用方法。

### 提示词
```
这是路径为go/test/map.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
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