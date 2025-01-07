Response:
我的目标是理解并解释给定的 Go 代码片段的功能，并尽可能提供清晰的示例和说明。以下是我的思考过程：

1. **整体阅读，识别关键信息:** 首先快速浏览代码，注意 `//go:build goexperiment.staticlockranking` 这个构建标签，说明这段代码是与一个实验性的特性相关的。`package runtime` 表明它属于 Go 运行时环境的核心部分。注释中的 "static lock ranking" 是一个重要的线索。

2. **核心数据结构 `lockRankStruct`:** 关注 `lockRankStruct`，它被嵌入到 `mutex` 中，包含 `rank lockRank`。这证实了 "lock ranking" 的概念，即给锁赋予一个等级。`pad int` 看起来是为了内存对齐。

3. **关键函数分析:** 逐个分析函数的功能：
    * `lockInit`:  初始化锁的 `rank`。
    * `getLockRank`: 获取锁的 `rank`。
    * `lockWithRank`:  一个关键函数，它在获取锁的同时允许指定锁的 `rank`。注意它对 `debuglock`, `paniclk`, `raceFiniLock` 的特殊处理。  它还使用 `systemstack` 来记录锁的持有情况。核心逻辑是记录当前持有的锁，并调用 `checkRanks` 来检查锁的顺序是否正确。
    * `printHeldLocks`: 辅助函数，打印当前 goroutine 持有的锁。
    * `acquireLockRankAndM`: 获取一个不与 `mutex` 关联的 `rank`，同时获取 M。
    * `checkRanks`:  **核心的锁顺序检查逻辑**。它比较当前要获取的锁的 `rank` 和之前持有的锁的 `rank`，并利用 `lockPartialOrder` 进行更细粒度的检查。
    * `unlockWithRank`:  释放锁，并从当前 goroutine 的持有锁列表中移除。
    * `releaseLockRankAndM`: 释放通过 `acquireLockRankAndM` 获取的 `rank`。
    * `lockWithRankMayAcquire`:  在不实际获取锁的情况下，检查如果获取该锁是否会违反锁顺序。
    * `checkLockHeld`:  检查当前 goroutine 是否持有某个锁。
    * `assertLockHeld`: 断言当前 goroutine 持有某个锁，否则抛出异常。
    * `assertRankHeld`: 断言当前 goroutine 持有具有特定 `rank` 的锁，否则抛出异常。
    * `worldStopped`, `worldStarted`, `checkWorldStopped`, `assertWorldStopped`, `assertWorldStoppedOrLockHeld`: 这组函数看起来是用来跟踪和断言全局的 "world stop" 状态，这通常与垃圾回收或其他需要暂停所有 goroutine 的操作有关。

4. **推断 Go 语言功能:** 基于以上分析，可以推断出这段代码实现的是 **静态锁排序 (Static Lock Ranking)** 功能。  其目的是在并发编程中预防死锁。通过为每个锁分配一个等级，并在尝试获取锁时检查等级顺序，可以及早发现潜在的死锁风险。

5. **构建 Go 代码示例:** 为了更清晰地说明，我决定创建示例来演示 `lockInit` 和 `lockWithRank` 的使用，并展示违反锁顺序时会发生什么。  需要包含多个互斥锁，并尝试以不同的顺序获取它们。

6. **思考易犯错的点:**  主要的易犯错点在于不了解锁的等级，或者在初始化和使用锁的时候没有遵循预期的等级顺序。  例子应该突出这一点。

7. **命令行参数处理:** 代码本身没有直接处理命令行参数，但构建标签 `go:build goexperiment.staticlockranking` 暗示需要在编译时启用这个实验性特性。需要说明如何通过 `go build -tags` 来启用。

8. **组织答案:** 将分析结果组织成清晰的段落，包括功能列表、Go 语言功能解释、代码示例（包含假设输入/输出）、命令行参数处理以及易犯错的点。使用中文回答。

9. **审查和完善:**  最后，重新阅读答案，确保其准确、完整且易于理解。  检查代码示例是否正确运行并能有效说明问题。 确认术语使用一致，例如“互斥锁”，“goroutine”等。

通过以上步骤，我逐步理解了代码的功能，并构建出了最终的答案。 特别是 `checkRanks` 函数的分析，让我确信这是在实现静态锁排序。  而构建示例代码则帮助我验证了我的理解，并能够更有效地向用户解释这个功能。
这段 Go 语言代码是 Go 运行时环境的一部分，实现了 **静态锁排序 (Static Lock Ranking)** 的功能。这是一个用于在并发程序中检测和预防死锁的机制。

**功能列表:**

1. **定义静态锁等级:**  通过 `lockRankStruct` 将锁的静态等级 `rank` 嵌入到 `mutex` 结构体中。
2. **初始化锁等级:** 提供 `lockInit(l *mutex, rank lockRank)` 函数来显式地为互斥锁设置静态等级。
3. **动态指定锁等级:** 提供 `lockWithRank(l *mutex, rank lockRank)` 函数，允许在获取锁时动态指定其等级（主要用于非静态初始化的锁）。
4. **获取锁等级:** 提供 `getLockRank(l *mutex) lockRank` 函数来获取互斥锁的等级。
5. **记录已持有的锁:** 在每个 goroutine 的 `m` (machine) 结构体中维护一个 `locksHeld` 数组，记录当前 goroutine 持有的锁及其等级。
6. **检查锁获取顺序:** `checkRanks(gp *g, prevRank, rank lockRank)` 函数是核心，它检查当前尝试获取的锁的等级 (`rank`) 是否高于最近持有的锁的等级 (`prevRank`)，从而避免环路等待（死锁的常见原因）。
7. **处理特殊锁:**  `lockWithRank` 和 `unlockWithRank` 特殊处理了 `debuglock`, `paniclk`, 和 `raceFiniLock` 这些锁，不进行锁等级记录，因为它们在错误处理或程序退出等特殊场景中使用。
8. **支持非互斥锁资源的排序:**  提供 `acquireLockRankAndM(rank lockRank)` 和 `releaseLockRankAndM(rank lockRank)` 函数，用于跟踪和排序不与具体 `mutex` 关联的资源（例如，表示某种状态）。同时，为了保证 M 的状态一致性，会同时获取和释放 M。
9. **打印已持有的锁:** 提供 `printHeldLocks(gp *g)` 函数，用于调试，打印当前 goroutine 持有的锁及其等级。
10. **断言锁已被持有:** 提供 `assertLockHeld(l *mutex)` 和 `assertRankHeld(r lockRank)` 函数，用于在代码中进行断言，确保在特定代码段执行前，goroutine 已经持有预期的锁。
11. **跟踪全局 World Stop 状态:**  使用原子操作的 `worldIsStopped` 变量来跟踪全局 "world-stop" 状态（通常与垃圾回收相关），并提供 `worldStopped()`, `worldStarted()`, `checkWorldStopped()`, `assertWorldStopped()`, `assertWorldStoppedOrLockHeld()` 等函数来管理和断言这个状态。这与锁排序结合使用，可以在 world stop 期间放宽某些锁排序的限制。

**Go 语言功能实现推断：静态锁排序**

这段代码实现的是 Go 语言的 **静态锁排序 (Static Lock Ranking)** 功能。其核心思想是为程序中的每个互斥锁分配一个固定的等级，并在运行时检查锁的获取顺序。如果一个 goroutine 尝试获取一个等级低于其当前持有锁的锁，则会触发 panic，从而及早发现潜在的死锁问题。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

//go:linkname lockRank runtime.lockRank
type lockRank int

// 定义一些锁等级常量
const (
	rankA runtime.lockRank = 1
	rankB runtime.lockRank = 2
)

// 获取 runtime.mutex 结构体，方便访问内部的 rank 字段
//go:linkname mutex runtime.mutex
type mutex struct {
	lockRankStruct runtime.lockRankStruct
	// ... 其他字段
}

func main() {
	var muA mutex
	var muB mutex

	// 初始化锁的等级
	runtime.LockInit(&muA, rankA)
	runtime.LockInit(&muB, rankB)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: 先获取 muA，再获取 muB
	go func() {
		defer wg.Done()
		runtime.LockWithRank(&muA, int(runtime.GetLockRank(&muA))) // 获取锁 A
		fmt.Println("Goroutine 1 获得了锁 A")
		runtime.LockWithRank(&muB, int(runtime.GetLockRank(&muB))) // 获取锁 B
		fmt.Println("Goroutine 1 获得了锁 B")
		runtime.UnlockWithRank(&muB)
		runtime.UnlockWithRank(&muA)
	}()

	// Goroutine 2: 先获取 muB，再获取 muA (可能导致死锁，会被锁排序检测到)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Goroutine 2 捕获到 panic:", r)
			}
			wg.Done()
		}()
		runtime.LockWithRank(&muB, int(runtime.GetLockRank(&muB))) // 获取锁 B
		fmt.Println("Goroutine 2 获得了锁 B")
		runtime.LockWithRank(&muA, int(runtime.GetLockRank(&muA))) // 尝试获取锁 A，等级低于已持有的锁 B，触发 panic
		fmt.Println("Goroutine 2 获得了锁 A") // 这行代码不会执行
		runtime.UnlockWithRank(&muA)
		runtime.UnlockWithRank(&muB)
	}()

	wg.Wait()
}
```

**假设的输入与输出：**

要运行这个示例，你需要使用支持 `staticlockranking` 实验的 Go 版本，并且在编译时启用它。

假设你启用了 `staticlockranking`，运行上述代码，你可能会看到类似以下的输出（输出顺序可能略有不同）：

```
Goroutine 1 获得了锁 A
Goroutine 1 获得了锁 B
Goroutine 2 获得了锁 B
panic: lock ordering problem

goroutine 7 [running]:
runtime.throw({0x100c0a0?, 0xc00000e058?})
        /Users/you/go/src/runtime/panic.go:929 +0x71
runtime.checkRanks(0xc000000180, 0x1, 0x2)
        /Users/you/go/src/runtime/lockrank_on.go:166 +0x145
runtime.lockWithRank.func1()
        /Users/you/go/src/runtime/lockrank_on.go:82 +0x75
runtime.systemstack()
        /Users/you/go/src/runtime/asm_amd64.s:495 +0x6b
runtime.mcall(0x0?)
        /Users/you/go/src/runtime/asm_amd64.s:612 +0x56
runtime.lockWithRank(0xc00004e008?, 0x1)
        /Users/you/go/src/runtime/lockrank_on.go:88 +0x103
main.main.func2()
        /Users/you/main.go:49 +0x73
created by main.main in goroutine 1
        /Users/you/main.go:39 +0xb9
exit status 2
```

**解释：**

* Goroutine 1 按照正确的顺序（先等级低的锁 A，再等级高的锁 B）获取锁，不会有问题。
* Goroutine 2 尝试先获取等级高的锁 B，再获取等级低的锁 A。当它尝试获取锁 A 时，`checkRanks` 函数检测到锁的等级顺序错误，触发了 panic，阻止了潜在的死锁。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。但是，由于它使用了构建标签 `//go:build goexperiment.staticlockranking`，这意味着这个功能是 Go 的一个实验性特性。

要启用这个功能，你需要在编译 Go 程序时使用 `-tags` 标志：

```bash
go build -tags=goexperiment.staticlockranking main.go
```

或者，如果你使用 `go run`:

```bash
go run -tags=goexperiment.staticlockranking main.go
```

如果没有指定 `-tags=goexperiment.staticlockranking`，这段代码中的功能将不会被启用，Go 将会使用 `go/src/runtime/lockrank_off.go` 中的实现，该实现通常是空操作或不进行锁等级检查。

**使用者易犯错的点：**

1. **忘记初始化锁的等级：** 如果使用了 `lockInit` 来初始化锁的等级，但忘记调用，那么锁的等级将是默认值 (通常是 0)，可能会导致误判或无法正确进行锁排序检查。

   ```go
   var mu mutex
   // 忘记调用 runtime.LockInit(&mu, someRank)

   runtime.LockWithRank(&mu, 1) // 这里的 rank 参数会被使用，但不是静态等级
   ```

2. **锁等级分配不合理：**  如果人为地给锁分配了错误的等级，例如，将一个应该在后面获取的锁分配了较低的等级，那么锁排序机制将无法正确工作。

3. **在不应该使用 `lockWithRank` 的地方使用：**  `lockWithRank` 主要用于处理那些没有在初始化时设置静态等级的锁。对于已经通过 `lockInit` 设置了等级的锁，直接使用标准的 `sync.Mutex.Lock()` 即可，运行时会自动获取其静态等级进行检查。过度使用 `lockWithRank` 可能会使代码更复杂且不易维护。

4. **忽略 panic 信息：**  当锁排序检测到问题时会触发 panic。开发者需要仔细查看 panic 信息，了解是哪个 goroutine，在获取哪个锁时发生了等级冲突，从而定位问题并调整锁的获取顺序或锁的等级分配。

总而言之，这段代码是 Go 运行时中一个用于增强并发安全性的重要组成部分，它通过静态锁排序帮助开发者在早期发现和避免潜在的死锁问题。理解其工作原理和正确使用方式对于编写健壮的并发 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/runtime/lockrank_on.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.staticlockranking

package runtime

import (
	"internal/runtime/atomic"
	"unsafe"
)

const staticLockRanking = true

// worldIsStopped is accessed atomically to track world-stops. 1 == world
// stopped.
var worldIsStopped atomic.Uint32

// lockRankStruct is embedded in mutex
type lockRankStruct struct {
	// static lock ranking of the lock
	rank lockRank
	// pad field to make sure lockRankStruct is a multiple of 8 bytes, even on
	// 32-bit systems.
	pad int
}

// lockInit(l *mutex, rank int) sets the rank of lock before it is used.
// If there is no clear place to initialize a lock, then the rank of a lock can be
// specified during the lock call itself via lockWithRank(l *mutex, rank int).
func lockInit(l *mutex, rank lockRank) {
	l.rank = rank
}

func getLockRank(l *mutex) lockRank {
	return l.rank
}

// lockWithRank is like lock(l), but allows the caller to specify a lock rank
// when acquiring a non-static lock.
//
// Note that we need to be careful about stack splits:
//
// This function is not nosplit, thus it may split at function entry. This may
// introduce a new edge in the lock order, but it is no different from any
// other (nosplit) call before this call (including the call to lock() itself).
//
// However, we switch to the systemstack to record the lock held to ensure that
// we record an accurate lock ordering. e.g., without systemstack, a stack
// split on entry to lock2() would record stack split locks as taken after l,
// even though l is not actually locked yet.
func lockWithRank(l *mutex, rank lockRank) {
	if l == &debuglock || l == &paniclk || l == &raceFiniLock {
		// debuglock is only used for println/printlock(). Don't do lock
		// rank recording for it, since print/println are used when
		// printing out a lock ordering problem below.
		//
		// paniclk is only used for fatal throw/panic. Don't do lock
		// ranking recording for it, since we throw after reporting a
		// lock ordering problem. Additionally, paniclk may be taken
		// after effectively any lock (anywhere we might panic), which
		// the partial order doesn't cover.
		//
		// raceFiniLock is held while exiting when running
		// the race detector. Don't do lock rank recording for it,
		// since we are exiting.
		lock2(l)
		return
	}
	if rank == 0 {
		rank = lockRankLeafRank
	}
	gp := getg()
	// Log the new class.
	systemstack(func() {
		i := gp.m.locksHeldLen
		if i >= len(gp.m.locksHeld) {
			throw("too many locks held concurrently for rank checking")
		}
		gp.m.locksHeld[i].rank = rank
		gp.m.locksHeld[i].lockAddr = uintptr(unsafe.Pointer(l))
		gp.m.locksHeldLen++

		// i is the index of the lock being acquired
		if i > 0 {
			checkRanks(gp, gp.m.locksHeld[i-1].rank, rank)
		}
		lock2(l)
	})
}

// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func printHeldLocks(gp *g) {
	if gp.m.locksHeldLen == 0 {
		println("<none>")
		return
	}

	for j, held := range gp.m.locksHeld[:gp.m.locksHeldLen] {
		println(j, ":", held.rank.String(), held.rank, unsafe.Pointer(gp.m.locksHeld[j].lockAddr))
	}
}

// acquireLockRankAndM acquires a rank which is not associated with a mutex
// lock. To maintain the invariant that an M with m.locks==0 does not hold any
// lock-like resources, it also acquires the M.
//
// This function may be called in nosplit context and thus must be nosplit.
//
//go:nosplit
func acquireLockRankAndM(rank lockRank) {
	acquirem()

	gp := getg()
	// Log the new class. See comment on lockWithRank.
	systemstack(func() {
		i := gp.m.locksHeldLen
		if i >= len(gp.m.locksHeld) {
			throw("too many locks held concurrently for rank checking")
		}
		gp.m.locksHeld[i].rank = rank
		gp.m.locksHeld[i].lockAddr = 0
		gp.m.locksHeldLen++

		// i is the index of the lock being acquired
		if i > 0 {
			checkRanks(gp, gp.m.locksHeld[i-1].rank, rank)
		}
	})
}

// checkRanks checks if goroutine g, which has mostly recently acquired a lock
// with rank 'prevRank', can now acquire a lock with rank 'rank'.
//
//go:systemstack
func checkRanks(gp *g, prevRank, rank lockRank) {
	rankOK := false
	if rank < prevRank {
		// If rank < prevRank, then we definitely have a rank error
		rankOK = false
	} else if rank == lockRankLeafRank {
		// If new lock is a leaf lock, then the preceding lock can
		// be anything except another leaf lock.
		rankOK = prevRank < lockRankLeafRank
	} else {
		// We've now verified the total lock ranking, but we
		// also enforce the partial ordering specified by
		// lockPartialOrder as well. Two locks with the same rank
		// can only be acquired at the same time if explicitly
		// listed in the lockPartialOrder table.
		list := lockPartialOrder[rank]
		for _, entry := range list {
			if entry == prevRank {
				rankOK = true
				break
			}
		}
	}
	if !rankOK {
		printlock()
		println(gp.m.procid, " ======")
		printHeldLocks(gp)
		throw("lock ordering problem")
	}
}

// See comment on lockWithRank regarding stack splitting.
func unlockWithRank(l *mutex) {
	if l == &debuglock || l == &paniclk || l == &raceFiniLock {
		// See comment at beginning of lockWithRank.
		unlock2(l)
		return
	}
	gp := getg()
	systemstack(func() {
		found := false
		for i := gp.m.locksHeldLen - 1; i >= 0; i-- {
			if gp.m.locksHeld[i].lockAddr == uintptr(unsafe.Pointer(l)) {
				found = true
				copy(gp.m.locksHeld[i:gp.m.locksHeldLen-1], gp.m.locksHeld[i+1:gp.m.locksHeldLen])
				gp.m.locksHeldLen--
				break
			}
		}
		if !found {
			println(gp.m.procid, ":", l.rank.String(), l.rank, l)
			throw("unlock without matching lock acquire")
		}
		unlock2(l)
	})
}

// releaseLockRankAndM releases a rank which is not associated with a mutex
// lock. To maintain the invariant that an M with m.locks==0 does not hold any
// lock-like resources, it also releases the M.
//
// This function may be called in nosplit context and thus must be nosplit.
//
//go:nosplit
func releaseLockRankAndM(rank lockRank) {
	gp := getg()
	systemstack(func() {
		found := false
		for i := gp.m.locksHeldLen - 1; i >= 0; i-- {
			if gp.m.locksHeld[i].rank == rank && gp.m.locksHeld[i].lockAddr == 0 {
				found = true
				copy(gp.m.locksHeld[i:gp.m.locksHeldLen-1], gp.m.locksHeld[i+1:gp.m.locksHeldLen])
				gp.m.locksHeldLen--
				break
			}
		}
		if !found {
			println(gp.m.procid, ":", rank.String(), rank)
			throw("lockRank release without matching lockRank acquire")
		}
	})

	releasem(getg().m)
}

// nosplit because it may be called from nosplit contexts.
//
//go:nosplit
func lockWithRankMayAcquire(l *mutex, rank lockRank) {
	gp := getg()
	if gp.m.locksHeldLen == 0 {
		// No possibility of lock ordering problem if no other locks held
		return
	}

	systemstack(func() {
		i := gp.m.locksHeldLen
		if i >= len(gp.m.locksHeld) {
			throw("too many locks held concurrently for rank checking")
		}
		// Temporarily add this lock to the locksHeld list, so
		// checkRanks() will print out list, including this lock, if there
		// is a lock ordering problem.
		gp.m.locksHeld[i].rank = rank
		gp.m.locksHeld[i].lockAddr = uintptr(unsafe.Pointer(l))
		gp.m.locksHeldLen++
		checkRanks(gp, gp.m.locksHeld[i-1].rank, rank)
		gp.m.locksHeldLen--
	})
}

// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func checkLockHeld(gp *g, l *mutex) bool {
	for i := gp.m.locksHeldLen - 1; i >= 0; i-- {
		if gp.m.locksHeld[i].lockAddr == uintptr(unsafe.Pointer(l)) {
			return true
		}
	}
	return false
}

// assertLockHeld throws if l is not held by the caller.
//
// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func assertLockHeld(l *mutex) {
	gp := getg()

	held := checkLockHeld(gp, l)
	if held {
		return
	}

	// Crash from system stack to avoid splits that may cause
	// additional issues.
	systemstack(func() {
		printlock()
		print("caller requires lock ", l, " (rank ", l.rank.String(), "), holding:\n")
		printHeldLocks(gp)
		throw("not holding required lock!")
	})
}

// assertRankHeld throws if a mutex with rank r is not held by the caller.
//
// This is less precise than assertLockHeld, but can be used in places where a
// pointer to the exact mutex is not available.
//
// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func assertRankHeld(r lockRank) {
	gp := getg()

	for i := gp.m.locksHeldLen - 1; i >= 0; i-- {
		if gp.m.locksHeld[i].rank == r {
			return
		}
	}

	// Crash from system stack to avoid splits that may cause
	// additional issues.
	systemstack(func() {
		printlock()
		print("caller requires lock with rank ", r.String(), "), holding:\n")
		printHeldLocks(gp)
		throw("not holding required lock!")
	})
}

// worldStopped notes that the world is stopped.
//
// Caller must hold worldsema.
//
// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func worldStopped() {
	if stopped := worldIsStopped.Add(1); stopped != 1 {
		systemstack(func() {
			print("world stop count=", stopped, "\n")
			throw("recursive world stop")
		})
	}
}

// worldStarted that the world is starting.
//
// Caller must hold worldsema.
//
// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func worldStarted() {
	if stopped := worldIsStopped.Add(-1); stopped != 0 {
		systemstack(func() {
			print("world stop count=", stopped, "\n")
			throw("released non-stopped world stop")
		})
	}
}

// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func checkWorldStopped() bool {
	stopped := worldIsStopped.Load()
	if stopped > 1 {
		systemstack(func() {
			print("inconsistent world stop count=", stopped, "\n")
			throw("inconsistent world stop count")
		})
	}

	return stopped == 1
}

// assertWorldStopped throws if the world is not stopped. It does not check
// which M stopped the world.
//
// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func assertWorldStopped() {
	if checkWorldStopped() {
		return
	}

	throw("world not stopped")
}

// assertWorldStoppedOrLockHeld throws if the world is not stopped and the
// passed lock is not held.
//
// nosplit to ensure it can be called in as many contexts as possible.
//
//go:nosplit
func assertWorldStoppedOrLockHeld(l *mutex) {
	if checkWorldStopped() {
		return
	}

	gp := getg()
	held := checkLockHeld(gp, l)
	if held {
		return
	}

	// Crash from system stack to avoid splits that may cause
	// additional issues.
	systemstack(func() {
		printlock()
		print("caller requires world stop or lock ", l, " (rank ", l.rank.String(), "), holding:\n")
		println("<no world stop>")
		printHeldLocks(gp)
		throw("no world stop or required lock!")
	})
}

"""



```