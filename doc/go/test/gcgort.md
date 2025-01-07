Response: Let's break down the thought process to analyze the given Go code.

1. **Understand the Goal:** The initial comment is crucial: "Test independent goroutines modifying a comprehensive variety of vars during aggressive garbage collection."  This immediately tells us the primary purpose is testing the interaction between concurrent modifications of variables and the garbage collector. The mention of "catch GC regressions like fixedbugs/issue22781.go" reinforces this.

2. **Identify Key Components:** Scan the `main` function and top-level declarations.
    * `debug.SetGCPercent(1)`:  This stands out. Setting the GC percentage to 1 forces the garbage collector to run very aggressively.
    * `sync.WaitGroup`:  This indicates the use of goroutines and waiting for their completion.
    * Nested loops with `goroutines`, `allocs`:  This suggests multiple goroutines are being launched.
    * The `types` variable, a slice of `modifier`:  This looks like a central data structure defining the test cases.
    * The `modifier` struct and its methods (`t`, `pointerT`, etc.): This likely defines the different kinds of modifications being performed.

3. **Analyze the `main` Function's Logic:**
    * The outer loop iterates `goroutines` times, launching that many concurrent "test runs."
    * The inner loop iterates over each `modifier` in the `types` slice.
    * `t.valid()`: This checks if the `modifier` is properly configured. Good defensive programming.
    * Another `sync.WaitGroup` (`wg2`) is used *within* each outer goroutine. This suggests a second level of concurrency.
    * The innermost loop iterates `allocs` times.
    * Inside the innermost loop, *eight* more goroutines are launched, each calling a different modification method (`f.t()`, `f.pointerT()`, etc.) of the current `modifier`.

4. **Deconstruct the `modifier` Struct and its Methods:**
    * The `modifier` struct holds a `name` and eight function fields. These function fields are the core of the test, defining how each data type is modified.
    * The `valid()` method ensures all the function fields are populated.
    * Each `modifier` in the `types` slice corresponds to a specific Go data type (bool, uint8, int, string, struct, etc.).
    * The methods within each `modifier` demonstrate different ways to modify that data type: direct modification, modification via a pointer, modification of elements within arrays, slices, maps, channels, and through interfaces.

5. **Infer the Purpose:** Based on the aggressive GC setting, the concurrent modifications, and the variety of data types, the core function is to stress-test the Go runtime's garbage collector and ensure it correctly handles concurrent modifications to different types of variables. It's designed to detect data races or other memory corruption issues that might arise under heavy GC pressure.

6. **Formulate the Explanation:** Now, put it all together in a clear and structured manner:
    * Start with a high-level summary of the code's purpose.
    * Explain the aggressive GC setting and its significance.
    * Detail the concurrency model (multiple levels of goroutines).
    * Explain the `modifier` struct and how it organizes the test cases.
    * Provide a concrete example using the "bool" `modifier` to illustrate how the different modification methods work.
    * Explain the lack of command-line arguments.
    * Consider potential pitfalls for users (though this particular code isn't designed for external use, so this section is less relevant).

7. **Refine and Organize:**  Review the explanation for clarity, accuracy, and completeness. Ensure the code examples are correct and easy to understand. Use headings and bullet points to improve readability. For example, grouping the different modification methods under the "bool" example makes it easier to grasp.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:**  Maybe this is just testing basic concurrency.
* **Correction:** The `debug.SetGCPercent(1)` is a strong indicator that the *garbage collector* is the primary target.
* **Initial Thought:** The `modifier` struct seems a bit complex.
* **Clarification:**  Realize that it's designed to systematically test modifications across various ways of accessing and changing data (direct, pointer, collection elements).
* **Consideration:** Should I explain every single data type?
* **Decision:** No, focusing on one or two key examples (like "bool") is sufficient to illustrate the pattern. Mentioning the range of types is important, though.
* **Review:**  Ensure the language is precise. For instance, instead of saying "it runs many things at once," specify "it launches multiple goroutines."

By following these steps, combining code analysis with an understanding of the problem domain (garbage collection), and iteratively refining the explanation, we can arrive at a comprehensive and accurate summary of the code's functionality.
这段Go语言代码片段的主要功能是**并发地对多种数据类型的变量进行读写操作，并在高压力的垃圾回收环境下测试Go语言的内存管理机制和并发安全性。**

更具体地说，这段代码旨在通过以下方式来检测Go语言运行时（runtime）的潜在问题，特别是与垃圾回收（GC）相关的bug：

1. **模拟高并发场景：** 代码启动了多层嵌套的goroutine，模拟了高并发的环境。外层循环启动`goroutines`个goroutine，内层循环针对每种数据类型（`types`）启动一系列goroutine进行修改。

2. **针对多种数据类型：** `types`变量包含了Go语言中常见的各种数据类型（bool, int, float, complex, string, struct等），以及它们的指针、数组、切片、map、channel和interface形式。

3. **并发修改：**  每个内部的goroutine都会对特定类型的变量进行修改操作。修改操作涵盖了直接赋值、通过指针修改、修改数组/切片元素、修改map的键值对、通过channel发送接收数据以及通过interface进行类型断言和修改。

4. **高压力的垃圾回收：** `debug.SetGCPercent(1)` 将垃圾回收的触发阈值设置为1%，这意味着只要有少量的新内存分配，就会触发垃圾回收。这使得垃圾回收器更加频繁地运行，从而增加了在并发修改数据时发生竞争条件或内存不一致问题的可能性。

**推理出的Go语言功能实现：**

这段代码是Go语言运行时或标准库的一部分，用于进行**压力测试和回归测试**，特别是在垃圾回收机制方面。它的目的是验证在高并发和高GC压力下，Go程序的内存管理和并发控制是否正确。

**Go代码举例说明：**

以下代码展示了针对 `bool` 类型进行的并发修改操作，对应 `types` 数组中第一个 `modifier` 结构体定义的功能：

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
)

func main() {
	var a bool
	var pointerA *bool = new(bool)
	var arrayA [9]bool
	var sliceA []bool = make([]bool, 9)
	var mapA map[bool]bool = make(map[bool]bool)
	var mapPointerKeyA map[*bool]bool = make(map[*bool]bool)
	var chanA chan bool = make(chan bool)
	var interfaceA interface{} = false

	var wg sync.WaitGroup
	const mods = 8 // 模拟修改次数

	// 修改 bool 类型变量
	wg.Add(1)
	go func() {
		for i := 0; i < mods; i++ {
			a = !a
			runtime.Gosched()
		}
		wg.Done()
	}()

	// 修改 bool 指针指向的值
	wg.Add(1)
	go func() {
		for i := 0; i < mods; i++ {
			*pointerA = !*pointerA
			runtime.Gosched()
		}
		wg.Done()
	}()

	// 修改 bool 数组的元素
	wg.Add(1)
	go func() {
		for i := 0; i < mods; i++ {
			for j := 0; j < len(arrayA); j++ {
				arrayA[j] = !arrayA[j]
				runtime.Gosched()
			}
		}
		wg.Done()
	}()

	// ... (类似的 goroutine 用于修改 slice, map, channel, interface)

	wg.Wait()

	fmt.Println("bool:", a)
	fmt.Println("pointerA:", *pointerA)
	fmt.Println("arrayA:", arrayA)
	fmt.Println("sliceA:", sliceA)
	// ... (打印其他变量的值)
}
```

**代码逻辑介绍（带假设的输入与输出）：**

假设 `goroutines = 2`, `allocs = 1`, `mods = 2`。

1. **初始化:**  `debug.SetGCPercent(1)` 设置高压 GC。 初始化一个 `sync.WaitGroup` 用于等待所有goroutine完成。

2. **外层循环:**  循环两次 (因为 `goroutines = 2`)。

3. **内层循环 (types):** 假设当前处理的是 `bool` 类型的 `modifier`。

4. **启动 goroutine (outer):** 启动一个新的 goroutine，传入 `bool` 类型的 `modifier` 实例。

5. **内部 WaitGroup:** 在这个外层 goroutine 内部，又创建了一个 `sync.WaitGroup` (`wg2`).

6. **内层循环 (allocs):** 循环一次 (因为 `allocs = 1`)。

7. **启动 goroutine (inner):** 针对 `bool` 类型的 `modifier`，启动 8 个 goroutine，分别调用 `f.t()`, `f.pointerT()`, `f.arrayT()` 等方法。

   * **`f.t()` (修改 `bool` 变量):**
     * 假设初始 `var a bool` 的值为 `false`。
     * 循环两次 (因为 `mods = 2`)：
       * 第一次：`a = !a` (a 变为 `true`)，`runtime.Gosched()` 让出 CPU 时间片。
       * 第二次：`a = !a` (a 变为 `false`)，`runtime.Gosched()`。
     * **假设输出:** 最终 `a` 的值可能是 `true` 或 `false`，取决于 goroutine 的执行顺序和 GC 的干扰。

   * **`f.pointerT()` (修改 `bool` 指针):**
     * 假设 `a := func() *bool { return new(bool) }()` 初始化指针指向的 `bool` 值为 `false`。
     * 循环两次：
       * 第一次：`*a = !*a` (指针指向的值变为 `true`)，`runtime.Gosched()`。
       * 第二次：`*a = !*a` (指针指向的值变为 `false`)，`runtime.Gosched()`。
     * **假设输出:** 最终 `*a` 的值可能是 `true` 或 `false`。

   * **其他 `f.*T()` 方法:**  类似的逻辑，并发地修改数组、切片、map、channel 和 interface 类型的变量。

8. **等待内部 goroutine 完成:**  `wg2.Wait()` 等待针对当前数据类型启动的所有内部 goroutine 完成。

9. **外层 goroutine 完成:** `wg.Done()` 通知外层的 `WaitGroup` 当前外层 goroutine 完成。

10. **等待所有外层 goroutine 完成:** `wg.Wait()` 等待所有外层 goroutine 完成，程序结束。

**命令行参数处理：**

这段代码本身**没有处理任何命令行参数**。它是一个测试程序，其行为完全由代码中的常量和逻辑控制。它通常作为Go语言测试套件的一部分运行，而不是直接由用户通过命令行调用。

**使用者易犯错的点：**

由于这段代码是用于Go语言运行时或标准库的内部测试，**普通开发者不会直接使用或修改这段代码**。因此，不存在普通使用者易犯错的点。

然而，如果开发者尝试编写类似的并发测试代码，可能会犯以下错误：

* **忘记使用 `sync.WaitGroup` 进行同步:**  导致主 goroutine 在其他 goroutine 完成之前就退出，无法正确检测并发问题。
* **数据竞争（Data Race）:**  多个 goroutine 并发读写共享变量，但没有使用互斥锁或其他同步机制保护，导致程序行为不可预测。 例如，如果多个 goroutine 同时修改同一个 map 的同一个键值对，可能导致 map 的内部状态损坏。
* **死锁（Deadlock）:**  多个 goroutine 互相等待对方释放资源，导致程序卡住。例如，在 channel 的使用中，如果发送和接收操作不匹配，可能导致死锁。
* **过度依赖 `runtime.Gosched()`:** 虽然 `runtime.Gosched()` 可以让出 CPU 时间片，但它并不能保证并发安全。过度使用可能掩盖真正的并发问题。
* **假设 goroutine 的执行顺序:**  Goroutine 的执行顺序是不确定的，依赖特定执行顺序的测试可能会产生误导性的结果。

**总结：**

这段 `go/test/gcgort.go` 代码是一个用于测试Go语言运行时在高并发和高GC压力下内存管理和并发安全性的内部测试工具。它通过并发地修改各种数据类型的变量来模拟复杂的场景，旨在发现潜在的bug和回归。普通开发者无需关心其内部实现，但可以借鉴其并发测试的思想和方法。

Prompt: 
```
这是路径为go/test/gcgort.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// run

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test independent goroutines modifying a comprehensive
// variety of vars during aggressive garbage collection.

// The point is to catch GC regressions like fixedbugs/issue22781.go

package main

import (
	"errors"
	"runtime"
	"runtime/debug"
	"sync"
)

const (
	goroutines = 8
	allocs     = 8
	mods       = 8

	length = 9
)

func main() {
	debug.SetGCPercent(1)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		for _, t := range types {
			err := t.valid()
			if err != nil {
				panic(err)
			}
			wg.Add(1)
			go func(f modifier) {
				var wg2 sync.WaitGroup
				for j := 0; j < allocs; j++ {
					wg2.Add(1)
					go func() {
						f.t()
						wg2.Done()
					}()
					wg2.Add(1)
					go func() {
						f.pointerT()
						wg2.Done()
					}()
					wg2.Add(1)
					go func() {
						f.arrayT()
						wg2.Done()
					}()
					wg2.Add(1)
					go func() {
						f.sliceT()
						wg2.Done()
					}()
					wg2.Add(1)
					go func() {
						f.mapT()
						wg2.Done()
					}()
					wg2.Add(1)
					go func() {
						f.mapPointerKeyT()
						wg2.Done()
					}()
					wg2.Add(1)
					go func() {
						f.chanT()
						wg2.Done()
					}()
					wg2.Add(1)
					go func() {
						f.interfaceT()
						wg2.Done()
					}()
				}
				wg2.Wait()
				wg.Done()
			}(t)
		}
	}
	wg.Wait()
}

type modifier struct {
	name           string
	t              func()
	pointerT       func()
	arrayT         func()
	sliceT         func()
	mapT           func()
	mapPointerKeyT func()
	chanT          func()
	interfaceT     func()
}

func (a modifier) valid() error {
	switch {
	case a.name == "":
		return errors.New("modifier without name")
	case a.t == nil:
		return errors.New(a.name + " missing t")
	case a.pointerT == nil:
		return errors.New(a.name + " missing pointerT")
	case a.arrayT == nil:
		return errors.New(a.name + " missing arrayT")
	case a.sliceT == nil:
		return errors.New(a.name + " missing sliceT")
	case a.mapT == nil:
		return errors.New(a.name + " missing mapT")
	case a.mapPointerKeyT == nil:
		return errors.New(a.name + " missing mapPointerKeyT")
	case a.chanT == nil:
		return errors.New(a.name + " missing chanT")
	case a.interfaceT == nil:
		return errors.New(a.name + " missing interfaceT")
	default:
		return nil
	}
}

var types = []modifier{
	modifier{
		name: "bool",
		t: func() {
			var a bool
			for i := 0; i < mods; i++ {
				a = !a
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *bool { return new(bool) }()
			for i := 0; i < mods; i++ {
				*a = !*a
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]bool{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] = !a[j]
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]bool, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] = !a[j]
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[bool]bool)
			for i := 0; i < mods; i++ {
				a[false] = !a[false]
				a[true] = !a[true]
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*bool]bool)
			for i := 0; i < length; i++ {
				a[new(bool)] = false
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, v := range a {
					a[k] = !v
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan bool)
			for i := 0; i < mods; i++ {
				go func() { a <- false }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(bool(false))
			for i := 0; i < mods; i++ {
				a = !a.(bool)
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "uint8",
		t: func() {
			var u uint8
			for i := 0; i < mods; i++ {
				u++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *uint8 { return new(uint8) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]uint8{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]uint8, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[uint8]uint8)
			for i := 0; i < length; i++ {
				a[uint8(i)] = uint8(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*uint8]uint8)
			for i := 0; i < length; i++ {
				a[new(uint8)] = uint8(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan uint8)
			for i := 0; i < mods; i++ {
				go func() { a <- uint8(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(uint8(0))
			for i := 0; i < mods; i++ {
				a = a.(uint8) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "uint16",
		t: func() {
			var u uint16
			for i := 0; i < mods; i++ {
				u++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *uint16 { return new(uint16) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]uint16{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]uint16, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[uint16]uint16)
			for i := 0; i < length; i++ {
				a[uint16(i)] = uint16(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*uint16]uint16)
			for i := 0; i < length; i++ {
				a[new(uint16)] = uint16(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan uint16)
			for i := 0; i < mods; i++ {
				go func() { a <- uint16(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(uint16(0))
			for i := 0; i < mods; i++ {
				a = a.(uint16) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "uint32",
		t: func() {
			var u uint32
			for i := 0; i < mods; i++ {
				u++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *uint32 { return new(uint32) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]uint32{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]uint32, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[uint32]uint32)
			for i := 0; i < length; i++ {
				a[uint32(i)] = uint32(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*uint32]uint32)
			for i := 0; i < length; i++ {
				a[new(uint32)] = uint32(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan uint32)
			for i := 0; i < mods; i++ {
				go func() { a <- uint32(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(uint32(0))
			for i := 0; i < mods; i++ {
				a = a.(uint32) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "uint64",
		t: func() {
			var u uint64
			for i := 0; i < mods; i++ {
				u++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *uint64 { return new(uint64) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]uint64{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]uint64, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[uint64]uint64)
			for i := 0; i < length; i++ {
				a[uint64(i)] = uint64(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*uint64]uint64)
			for i := 0; i < length; i++ {
				a[new(uint64)] = uint64(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan uint64)
			for i := 0; i < mods; i++ {
				go func() { a <- uint64(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(uint64(0))
			for i := 0; i < mods; i++ {
				a = a.(uint64) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "int8",
		t: func() {
			var u int8
			for i := 0; i < mods; i++ {
				u++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *int8 { return new(int8) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]int8{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]int8, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[int8]int8)
			for i := 0; i < length; i++ {
				a[int8(i)] = int8(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*int8]int8)
			for i := 0; i < length; i++ {
				a[new(int8)] = int8(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan int8)
			for i := 0; i < mods; i++ {
				go func() { a <- int8(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(int8(0))
			for i := 0; i < mods; i++ {
				a = a.(int8) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "int16",
		t: func() {
			var u int16
			for i := 0; i < mods; i++ {
				u++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *int16 { return new(int16) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]int16{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]int16, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[int16]int16)
			for i := 0; i < length; i++ {
				a[int16(i)] = int16(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*int16]int16)
			for i := 0; i < length; i++ {
				a[new(int16)] = int16(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan int16)
			for i := 0; i < mods; i++ {
				go func() { a <- int16(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(int16(0))
			for i := 0; i < mods; i++ {
				a = a.(int16) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "int32",
		t: func() {
			var u int32
			for i := 0; i < mods; i++ {
				u++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *int32 { return new(int32) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]int32{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]int32, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[int32]int32)
			for i := 0; i < length; i++ {
				a[int32(i)] = int32(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*int32]int32)
			for i := 0; i < length; i++ {
				a[new(int32)] = int32(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan int32)
			for i := 0; i < mods; i++ {
				go func() { a <- int32(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(int32(0))
			for i := 0; i < mods; i++ {
				a = a.(int32) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "int64",
		t: func() {
			var u int64
			for i := 0; i < mods; i++ {
				u++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *int64 { return new(int64) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]int64{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]int64, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[int64]int64)
			for i := 0; i < length; i++ {
				a[int64(i)] = int64(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*int64]int64)
			for i := 0; i < length; i++ {
				a[new(int64)] = int64(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan int64)
			for i := 0; i < mods; i++ {
				go func() { a <- int64(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(int64(0))
			for i := 0; i < mods; i++ {
				a = a.(int64) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "float32",
		t: func() {
			u := float32(1.01)
			for i := 0; i < mods; i++ {
				u *= 1.01
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *float32 { return new(float32) }()
			*a = 1.01
			for i := 0; i < mods; i++ {
				*a *= 1.01
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]float32{}
			for i := 0; i < length; i++ {
				a[i] = float32(1.01)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] *= 1.01
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]float32, length)
			for i := 0; i < length; i++ {
				a[i] = float32(1.01)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] *= 1.01
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[float32]float32)
			for i := 0; i < length; i++ {
				a[float32(i)] = float32(i) + 0.01
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] *= 1.01
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*float32]float32)
			for i := 0; i < length; i++ {
				a[new(float32)] = float32(i) + 0.01
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] *= 1.01
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan float32)
			for i := 0; i < mods; i++ {
				go func() { a <- float32(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(float32(0))
			for i := 0; i < mods; i++ {
				a = a.(float32) * 1.01
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "float64",
		t: func() {
			u := float64(1.01)
			for i := 0; i < mods; i++ {
				u *= 1.01
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *float64 { return new(float64) }()
			*a = 1.01
			for i := 0; i < mods; i++ {
				*a *= 1.01
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]float64{}
			for i := 0; i < length; i++ {
				a[i] = float64(1.01)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] *= 1.01
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]float64, length)
			for i := 0; i < length; i++ {
				a[i] = float64(1.01)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] *= 1.01
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[float64]float64)
			for i := 0; i < length; i++ {
				a[float64(i)] = float64(i) + 0.01
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] *= 1.01
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*float64]float64)
			for i := 0; i < length; i++ {
				a[new(float64)] = float64(i) + 0.01
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] *= 1.01
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan float64)
			for i := 0; i < mods; i++ {
				go func() { a <- float64(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(float64(0))
			for i := 0; i < mods; i++ {
				a = a.(float64) * 1.01
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "complex64",
		t: func() {
			c := complex64(complex(float32(1.01), float32(1.01)))
			for i := 0; i < mods; i++ {
				c = complex(real(c)*1.01, imag(c)*1.01)
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *complex64 { return new(complex64) }()
			*a = complex64(complex(float32(1.01), float32(1.01)))
			for i := 0; i < mods; i++ {
				*a *= complex(real(*a)*1.01, imag(*a)*1.01)
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]complex64{}
			for i := 0; i < length; i++ {
				a[i] = complex64(complex(float32(1.01), float32(1.01)))
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] *= complex(real(a[j])*1.01, imag(a[j])*1.01)
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]complex64, length)
			for i := 0; i < length; i++ {
				a[i] = complex64(complex(float32(1.01), float32(1.01)))
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] *= complex(real(a[j])*1.01, imag(a[j])*1.01)
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[complex64]complex64)
			for i := 0; i < length; i++ {
				a[complex64(complex(float32(i), float32(i)))] = complex64(complex(float32(i), float32(i))) + 0.01
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] *= complex(real(a[k])*1.01, imag(a[k])*1.01)
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*complex64]complex64)
			for i := 0; i < length; i++ {
				a[new(complex64)] = complex64(complex(float32(i), float32(i))) + 0.01
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] *= complex(real(a[k])*1.01, imag(a[k])*1.01)
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan complex64)
			for i := 0; i < mods; i++ {
				go func() { a <- complex64(complex(float32(i), float32(i))) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(complex64(complex(float32(1.01), float32(1.01))))
			for i := 0; i < mods; i++ {
				a = a.(complex64) * complex(real(a.(complex64))*1.01, imag(a.(complex64))*1.01)
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "complex128",
		t: func() {
			c := complex128(complex(float64(1.01), float64(1.01)))
			for i := 0; i < mods; i++ {
				c = complex(real(c)*1.01, imag(c)*1.01)
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *complex128 { return new(complex128) }()
			*a = complex128(complex(float64(1.01), float64(1.01)))
			for i := 0; i < mods; i++ {
				*a *= complex(real(*a)*1.01, imag(*a)*1.01)
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]complex128{}
			for i := 0; i < length; i++ {
				a[i] = complex128(complex(float64(1.01), float64(1.01)))
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] *= complex(real(a[j])*1.01, imag(a[j])*1.01)
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]complex128, length)
			for i := 0; i < length; i++ {
				a[i] = complex128(complex(float64(1.01), float64(1.01)))
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] *= complex(real(a[j])*1.01, imag(a[j])*1.01)
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[complex128]complex128)
			for i := 0; i < length; i++ {
				a[complex128(complex(float64(i), float64(i)))] = complex128(complex(float64(i), float64(i))) + 0.01
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] *= complex(real(a[k])*1.01, imag(a[k])*1.01)
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*complex128]complex128)
			for i := 0; i < length; i++ {
				a[new(complex128)] = complex128(complex(float64(i), float64(i))) + 0.01
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] *= complex(real(a[k])*1.01, imag(a[k])*1.01)
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan complex128)
			for i := 0; i < mods; i++ {
				go func() { a <- complex128(complex(float64(i), float64(i))) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(complex128(complex(float64(1.01), float64(1.01))))
			for i := 0; i < mods; i++ {
				a = a.(complex128) * complex(real(a.(complex128))*1.01, imag(a.(complex128))*1.01)
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "byte",
		t: func() {
			var a byte
			for i := 0; i < mods; i++ {
				a++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *byte { return new(byte) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]byte{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]byte, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[byte]byte)
			for i := 0; i < length; i++ {
				a[byte(i)] = byte(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*byte]byte)
			for i := 0; i < length; i++ {
				a[new(byte)] = byte(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan byte)
			for i := 0; i < mods; i++ {
				go func() { a <- byte(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(byte(0))
			for i := 0; i < mods; i++ {
				a = a.(byte) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "rune",
		t: func() {
			var a rune
			for i := 0; i < mods; i++ {
				a++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *rune { return new(rune) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]rune{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]rune, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[rune]rune)
			for i := 0; i < length; i++ {
				a[rune(i)] = rune(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*rune]rune)
			for i := 0; i < length; i++ {
				a[new(rune)] = rune(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan rune)
			for i := 0; i < mods; i++ {
				go func() { a <- rune(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(rune(0))
			for i := 0; i < mods; i++ {
				a = a.(rune) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "uint",
		t: func() {
			var a uint
			for i := 0; i < mods; i++ {
				a++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *uint { return new(uint) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]uint{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]uint, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[uint]uint)
			for i := 0; i < length; i++ {
				a[uint(i)] = uint(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*uint]uint)
			for i := 0; i < length; i++ {
				a[new(uint)] = uint(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan uint)
			for i := 0; i < mods; i++ {
				go func() { a <- uint(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(uint(0))
			for i := 0; i < mods; i++ {
				a = a.(uint) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "int",
		t: func() {
			var a int
			for i := 0; i < mods; i++ {
				a++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *int { return new(int) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]int{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]int, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[int]int)
			for i := 0; i < length; i++ {
				a[int(i)] = int(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*int]int)
			for i := 0; i < length; i++ {
				a[new(int)] = int(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan int)
			for i := 0; i < mods; i++ {
				go func() { a <- int(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(int(0))
			for i := 0; i < mods; i++ {
				a = a.(int) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "uintptr",
		t: func() {
			var a uintptr
			for i := 0; i < mods; i++ {
				a++
				runtime.Gosched()
			}
		},
		pointerT: func() {
			a := func() *uintptr { return new(uintptr) }()
			for i := 0; i < mods; i++ {
				*a++
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]uintptr{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]uintptr, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j]++
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[uintptr]uintptr)
			for i := 0; i < length; i++ {
				a[uintptr(i)] = uintptr(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*uintptr]uintptr)
			for i := 0; i < length; i++ {
				a[new(uintptr)] = uintptr(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k]++
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan uintptr)
			for i := 0; i < mods; i++ {
				go func() { a <- uintptr(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(uintptr(0))
			for i := 0; i < mods; i++ {
				a = a.(uintptr) + 1
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "string",
		t: func() {
			var s string
			f := func(a string) string { return a }
			for i := 0; i < mods; i++ {
				s = str(i)
				s = f(s)
			}
		},
		pointerT: func() {
			a := func() *string { return new(string) }()
			for i := 0; i < mods; i++ {
				*a = str(i)
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]string{}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] = str(i)
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]string, length)
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j] = str(i)
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[string]string)
			for i := 0; i < length; i++ {
				a[string(i)] = str(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] = str(i)
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*string]string)
			for i := 0; i < length; i++ {
				a[new(string)] = str(i)
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for k, _ := range a {
					a[k] = str(i)
					runtime.Gosched()
				}
			}
		},
		chanT: func() {
			a := make(chan string)
			for i := 0; i < mods; i++ {
				go func() { a <- str(i) }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(str(0))
			f := func(a string) string { return a }
			for i := 0; i < mods; i++ {
				a = str(i)
				a = f(a.(string))
				runtime.Gosched()
			}
		},
	},
	modifier{
		name: "structT",
		t: func() {
			s := newStructT()
			for i := 0; i < mods; i++ {
				s.u8++
				s.u16++
				s.u32++
				s.u64++
				s.i8++
				s.i16++
				s.i32++
				s.i64++
				s.f32 *= 1.01
				s.f64 *= 1.01
				s.c64 = complex(real(s.c64)*1.01, imag(s.c64)*1.01)
				s.c128 = complex(real(s.c128)*1.01, imag(s.c128)*1.01)
				s.b++
				s.r++
				s.u++
				s.in++
				s.uip++
				s.s = str(i)
				runtime.Gosched()
			}
		},
		pointerT: func() {
			s := func() *structT {
				t := newStructT()
				return &t
			}()
			for i := 0; i < mods; i++ {
				s.u8++
				s.u16++
				s.u32++
				s.u64++
				s.i8++
				s.i16++
				s.i32++
				s.i64++
				s.f32 *= 1.01
				s.f64 *= 1.01
				s.c64 = complex(real(s.c64)*1.01, imag(s.c64)*1.01)
				s.c128 = complex(real(s.c128)*1.01, imag(s.c128)*1.01)
				s.b++
				s.r++
				s.u++
				s.in++
				s.uip++
				s.s = str(i)
				runtime.Gosched()
			}
		},
		arrayT: func() {
			a := [length]structT{}
			for i := 0; i < len(a); i++ {
				a[i] = newStructT()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j].u8++
					a[j].u16++
					a[j].u32++
					a[j].u64++
					a[j].i8++
					a[j].i16++
					a[j].i32++
					a[j].i64++
					a[j].f32 *= 1.01
					a[j].f64 *= 1.01
					a[j].c64 = complex(real(a[j].c64)*1.01, imag(a[j].c64)*1.01)
					a[j].c128 = complex(real(a[j].c128)*1.01, imag(a[j].c128)*1.01)
					a[j].b++
					a[j].r++
					a[j].u++
					a[j].in++
					a[j].uip++
					a[j].s = str(i)
					runtime.Gosched()
				}
			}
		},
		sliceT: func() {
			a := make([]structT, length)
			for i := 0; i < len(a); i++ {
				a[i] = newStructT()
			}
			for i := 0; i < mods; i++ {
				for j := 0; j < len(a); j++ {
					a[j].u8++
					a[j].u16++
					a[j].u32++
					a[j].u64++
					a[j].i8++
					a[j].i16++
					a[j].i32++
					a[j].i64++
					a[j].f32 *= 1.01
					a[j].f64 *= 1.01
					a[j].c64 = complex(real(a[j].c64)*1.01, imag(a[j].c64)*1.01)
					a[j].c128 = complex(real(a[j].c128)*1.01, imag(a[j].c128)*1.01)
					a[j].b++
					a[j].r++
					a[j].u++
					a[j].in++
					a[j].uip++
					a[j].s = str(i)
					runtime.Gosched()
				}
			}
		},
		mapT: func() {
			a := make(map[structT]structT)
			for i := 0; i < length; i++ {
				m := newStructT()
				m.in = i
				a[m] = newStructT()
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j, _ := range a {
					m := a[j]
					m.u8++
					m.u16++
					m.u32++
					m.u64++
					m.i8++
					m.i16++
					m.i32++
					m.i64++
					m.f32 *= 1.01
					m.f64 *= 1.01
					m.c64 = complex(real(a[j].c64)*1.01, imag(a[j].c64)*1.01)
					m.c128 = complex(real(a[j].c128)*1.01, imag(a[j].c128)*1.01)
					m.b++
					m.r++
					m.u++
					m.in++
					m.uip++
					m.s = str(i)
					a[j] = m
					runtime.Gosched()
				}
				runtime.Gosched()
			}
		},
		mapPointerKeyT: func() {
			a := make(map[*structT]structT)
			f := func() *structT {
				m := newStructT()
				return &m
			}
			for i := 0; i < length; i++ {
				m := f()
				m.in = i
				a[m] = newStructT()
				runtime.Gosched()
			}
			for i := 0; i < mods; i++ {
				for j, _ := range a {
					m := a[j]
					m.u8++
					m.u16++
					m.u32++
					m.u64++
					m.i8++
					m.i16++
					m.i32++
					m.i64++
					m.f32 *= 1.01
					m.f64 *= 1.01
					m.c64 = complex(real(a[j].c64)*1.01, imag(a[j].c64)*1.01)
					m.c128 = complex(real(a[j].c128)*1.01, imag(a[j].c128)*1.01)
					m.b++
					m.r++
					m.u++
					m.in++
					m.uip++
					m.s = str(i)
					a[j] = m
					runtime.Gosched()
				}
				runtime.Gosched()
			}
		},
		chanT: func() {
			a := make(chan structT)
			for i := 0; i < mods; i++ {
				go func() { a <- newStructT() }()
				<-a
				runtime.Gosched()
			}
		},
		interfaceT: func() {
			a := interface{}(newStructT())
			for i := 0; i < mods; i++ {
				a = a.(structT)
				runtime.Gosched()
			}
		},
	},
}

type structT struct {
	u8   uint8
	u16  uint16
	u32  uint32
	u64  uint64
	i8   int8
	i16  int16
	i32  int32
	i64  int64
	f32  float32
	f64  float64
	c64  complex64
	c128 complex128
	b    byte
	r    rune
	u    uint
	in   int
	uip  uintptr
	s    string
}

func newStructT() structT {
	return structT{
		f32:  1.01,
		f64:  1.01,
		c64:  complex(float32(1.01), float32(1.01)),
		c128: complex(float64(1.01), float64(1.01)),
	}
}

func str(in int) string {
	switch in % 3 {
	case 0:
		return "Hello"
	case 1:
		return "world"
	case 2:
		return "!"
	}
	return "?"
}

"""



```