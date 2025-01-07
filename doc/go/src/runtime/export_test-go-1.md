Response:
The user wants a summary of the functionality provided by the Go code snippet. This is the second part of a two-part request, so I need to provide a consolidated summary across both parts.

Here's a plan to generate the summary:
1. **Identify key functionalities:** Scan the code for exported functions, variables, and types, and group them by purpose.
2. **Summarize each functionality:** Briefly describe what each group of functions/variables/types does.
3. **Combine with the summary from part 1:** Integrate the summary from the first part (which I don't have access to but can infer based on common runtime functionalities and the structure of this code).
4. **Refine the summary:** Ensure the language is clear, concise, and in Chinese.
这段代码是 Go 运行时环境为了进行内部测试而导出的部分功能。它主要涵盖了以下几个方面的功能：

1. **性能指标收集**:
   -  `NewTimeHistogram`: 创建用于记录时间分布的直方图。
   -  `(*TimeHistogram).Record`: 记录一个时间段到直方图中。
   -  `TimeHistogramMetricsBuckets`:  可能用于定义时间直方图的桶。

2. **控制和获取运行时状态**:
   -  `SetIntArgRegs`:  设置或获取用于传递整数参数的寄存器数量（可能用于测试或调试目的）。
   -  `FinalizerGAsleep`:  检查 finalizer goroutine 是否处于休眠状态。
   -  `GCTestMoveStackOnNextCall`:  一个变量，可能用于触发在下次函数调用时移动 goroutine 的栈（用于 GC 测试）。
   -  `GCTestIsReachable`:  检查给定的指针是否可达（用于 GC 测试）。
     ```go
     // 假设我们想测试一个指针是否可达
     package main

     import (
         "fmt"
         "runtime"
         "unsafe"
     )

     //go:linkname GCTestIsReachable runtime.GCTestIsReachable
     func GCTestIsReachable(ptrs ...unsafe.Pointer) (mask uint64)

     func main() {
         var x int
         ptr := unsafe.Pointer(&x)
         mask := GCTestIsReachable(ptr)
         fmt.Printf("指针 %v 是否可达: %t\n", ptr, mask != 0)

         // 假设输入：一个指向局部变量 x 的指针
         // 预期输出： 指针 ... 是否可达: true (因为局部变量在栈上，当前可达)
     }
     ```
   -  `GCTestPointerClass`:  获取给定指针的类型信息（用于 GC 测试）。
     ```go
     // 假设我们想获取一个指针的类型信息
     package main

     import (
         "fmt"
         "runtime"
         "unsafe"
     )

     //go:linkname GCTestPointerClass runtime.GCTestPointerClass
     func GCTestPointerClass(p unsafe.Pointer) string

     func main() {
         var x int
         ptr := unsafe.Pointer(&x)
         class := GCTestPointerClass(ptr)
         fmt.Printf("指针 %v 的类型是: %s\n", ptr, class)

         // 假设输入：一个指向 int 类型变量 x 的指针
         // 预期输出： 指针 ... 的类型是: ... (具体的输出依赖于内部实现，可能是 "go.int" 或其他表示指针类型的字符串)
     }
     ```
   -  `Raceenabled`:  一个常量，指示 race 检测器是否启用。
   -  `GCBackgroundUtilization`, `GCGoalUtilization`, `DefaultHeapMinimum`, `MemoryLimitHeapGoalHeadroomPercent`, `MemoryLimitMinHeapGoalHeadroom`: 一些与 GC 相关的常量。

3. **GC 控制器的测试接口**:
   -  `GCController`:  一个结构体，代表 GC 控制器。
   -  `NewGCController`: 创建一个新的 GC 控制器实例，用于测试目的，允许指定 `gcPercent` 和 `memoryLimit`。
   -  `(*GCController).StartCycle`: 模拟启动一个 GC 周期。
   -  `(*GCController).AssistWorkPerByte`: 获取每个字节的辅助扫描工作量。
   -  `(*GCController).HeapGoal`: 获取堆的目标大小。
   -  `(*GCController).HeapLive`: 获取当前存活的堆大小。
   -  `(*GCController).HeapMarked`: 获取已标记的堆大小。
   -  `(*GCController).Triggered`: 获取触发 GC 的堆大小。
   -  `GCControllerReviseDelta`: 一个结构体，用于表示 GC 控制器的修订增量。
   -  `(*GCController).Revise`: 调整 GC 控制器的状态。
   -  `(*GCController).EndCycle`: 模拟结束一个 GC 周期。
   -  `(*GCController).AddIdleMarkWorker`, `(*GCController).NeedIdleMarkWorker`, `(*GCController).RemoveIdleMarkWorker`, `(*GCController).SetMaxIdleMarkWorkers`:  控制空闲标记 worker 的函数。

4. **辅助函数**:
   -  `Escape`:  用于阻止变量被编译器优化掉，常用于 benchmark 或测试。
   -  `Acquirem`, `Releasem`:  用于获取和释放与当前 goroutine 绑定的操作系统线程 (m)。
   -  `Timediv`:  可能是一个时间相关的辅助函数。

5. **PI 控制器**:
   -  `PIController`: 一个结构体，实现了 PI 控制器，可能用于 GC 相关的速率控制。
   -  `NewPIController`: 创建一个新的 PI 控制器实例。
   -  `(*PIController).Next`:  执行 PI 控制器的下一步计算。

6. **GC CPU 限制器**:
   -  `GCCPULimiter`: 一个结构体，用于限制 GC 使用的 CPU 资源。
   -  `NewGCCPULimiter`: 创建一个新的 GC CPU 限制器实例。
   -  `(*GCCPULimiter).Fill`, `(*GCCPULimiter).Capacity`, `(*GCCPULimiter).Overflow`, `(*GCCPULimiter).Limiting`, `(*GCCPULimiter).NeedUpdate`, `(*GCCPULimiter).StartGCTransition`, `(*GCCPULimiter).FinishGCTransition`, `(*GCCPULimiter).Update`, `(*GCCPULimiter).AddAssistTime`, `(*GCCPULimiter).ResetCapacity`:  用于操作和获取 GC CPU 限制器状态的函数。

7. **Scavenger (内存回收器) 测试接口**:
   -  `ScavengePercent`:  与内存回收相关的常量。
   -  `Scavenger`:  一个结构体，用于测试内存回收器。
   -  `(*Scavenger).Start`: 启动内存回收器 goroutine。
   -  `(*Scavenger).BlockUntilParked`: 阻塞直到内存回收器进入空闲状态。
   -  `(*Scavenger).Released`: 获取内存回收器释放的内存量。
   -  `(*Scavenger).Wake`: 唤醒空闲的内存回收器。
   -  `(*Scavenger).Stop`: 停止内存回收器。
   -  `ScavengeIndex`: 一个结构体，用于测试内存回收的索引结构。
   -  `NewScavengeIndex`: 创建一个新的 `ScavengeIndex` 实例。
   -  `(*ScavengeIndex).Find`:  在索引中查找可回收的内存块。
   -  `(*ScavengeIndex).AllocRange`, `(*ScavengeIndex).FreeRange`:  模拟分配和释放内存范围，用于测试索引的更新。
   -  `(*ScavengeIndex).ResetSearchAddrs`, `(*ScavengeIndex).NextGen`, `(*ScavengeIndex).SetEmpty`:  用于管理和操作回收索引的函数。
   -  `CheckPackScavChunkData`:  检查 `scavChunkData` 结构体的打包和解包过程。

8. **与 Arena 分配器相关的测试接口**:
   -  `ZeroBase`:  一个指向零地址的指针。
   -  `UserArenaChunkBytes`:  用户 arena 的 chunk 大小。
   -  `UserArena`: 一个结构体，代表用户 arena 分配器。
   -  `NewUserArena`: 创建一个新的用户 arena 分配器实例。
   -  `(*UserArena).New`: 在 arena 中分配一个新的对象。
     ```go
     // 假设我们想在一个 UserArena 中分配一个 int
     package main

     import (
         "fmt"
         "runtime"
     )

     //go:linkname NewUserArena runtime.NewUserArena
     func NewUserArena() *UserArena

     //go:linkname UserArenaNew runtime.(*UserArena).New
     func (a *UserArena) New(out *any)

     type UserArena runtime.UserArena

     func main() {
         arena := NewUserArena()
         var i int
         arena.New(&i)
         fmt.Printf("在 Arena 中分配的整数: %v\n", i)

         // 假设输入： 无
         // 预期输出： 在 Arena 中分配的整数: 0 (新分配的 int 的默认值)
     }
     ```
   -  `(*UserArena).Slice`: 在 arena 中分配一个 slice。
     ```go
     // 假设我们想在一个 UserArena 中分配一个 int 的 slice
     package main

     import (
         "fmt"
         "runtime"
         "reflect"
     )

     //go:linkname NewUserArena runtime.NewUserArena
     func NewUserArena() *UserArena

     //go:linkname UserArenaSlice runtime.(*UserArena).Slice
     func (a *UserArena) Slice(sl any, cap int)

     type UserArena runtime.UserArena

     func main() {
         arena := NewUserArena()
         var sl []int
         arena.Slice(&sl, 5)
         fmt.Printf("在 Arena 中分配的切片: %v, 容量: %d\n", sl, cap(sl))
         // 假设输入： 无
         // 预期输出： 在 Arena 中分配的切片: [], 容量: 5
     }
     ```
   -  `(*UserArena).Free`: 释放 arena 分配器。
   -  `GlobalWaitingArenaChunks`: 获取等待中的 arena chunks 数量。
   -  `UserArenaClone`: 克隆一个 arena 中的对象。

9. **Finalizer 相关**:
   -  `AlignUp`:  一个向上对齐的辅助函数。
   -  `BlockUntilEmptyFinalizerQueue`: 阻塞直到 finalizer 队列为空。

10. **栈帧信息**:
    - `FrameStartLine`: 获取栈帧的起始行号。
    ```go
    package main

    import (
        "fmt"
        "runtime"
    )

    //go:linkname FrameStartLine runtime.FrameStartLine
    func FrameStartLine(f *runtime.Frame) int

    func getFrame() *runtime.Frame {
        pc, _, _, _ := runtime.Caller(1)
        frames := runtime.CallersFrames([]uintptr{pc})
        frame, _ := frames.Next()
        return &frame
    }

    func main() {
        frame := getFrame()
        line := FrameStartLine(frame)
        fmt.Printf("当前栈帧的起始行号: %d\n", line)
        // 假设输入： 无
        // 预期输出： 当前栈帧的起始行号: ... (取决于 main 函数调用 getFrame 的行号)
    }
    ```

11. **持久化内存分配**:
    - `PersistentAlloc`: 分配不会被 Go GC 回收的内存。

12. **使用帧指针进行栈回溯**:
    - `FPCallers`: 使用帧指针进行栈回溯，获取返回地址。
    - `FramePointerEnabled`: 指示帧指针是否启用的常量。

13. **Pinner (防止对象被移动) 相关**:
    - `IsPinned`: 检查对象是否被 pin 住。
    - `GetPinCounter`: 获取 pin 计数器。
    - `SetPinnerLeakPanic`, `GetPinnerLeakPanic`: 设置和获取 pinner 泄露时的 panic 函数。

14. **泛型相关测试**:
    - `testUintptr`:  一个用于泛型测试的 `uintptr` 变量。
    - `MyGenericFunc`:  一个用于测试泛型的函数。

15. **不安全点**:
    - `UnsafePoint`: 检查给定的程序计数器 (pc) 是否在一个不安全点。

16. **TraceMap (追踪映射) 相关**:
    - `TraceMap`: 用于存储追踪信息的映射。
    - `(*TraceMap).PutString`: 将字符串添加到追踪映射中。
    - `(*TraceMap).Reset`: 重置追踪映射。

17. **GC Mark Done 调试**:
    - `SetSpinInGCMarkDone`: 设置在 GC 标记完成时是否自旋。
    - `GCMarkDoneRestarted`: 检查 GC 标记是否因为特定原因重启过。
    - `GCMarkDoneResetRestartFlag`: 重置 GC 标记重启标志。

18. **BitCursor (位游标) 相关**:
    - `BitCursor`: 用于在字节数组中进行位操作的游标。
    - `NewBitCursor`: 创建一个新的位游标。
    - `(*BitCursor).Write`: 从游标位置写入位。
    - `(*BitCursor).Offset`: 创建一个偏移指定位数的新的位游标。

总而言之，这段代码导出了 Go 运行时环境中的一些内部机制，主要是为了方便进行单元测试和性能分析，特别是针对垃圾回收器 (GC)、内存分配器 (包括 arena 分配器和持久化分配器)、以及 goroutine 调度的相关功能。 它提供了细粒度的控制和观察点，使得测试人员可以更深入地验证运行时环境的正确性和性能。

Prompt: 
```
这是路径为go/src/runtime/export_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
ram)(th).record(duration)
}

var TimeHistogramMetricsBuckets = timeHistogramMetricsBuckets

func SetIntArgRegs(a int) int {
	lock(&finlock)
	old := intArgRegs
	if a >= 0 {
		intArgRegs = a
	}
	unlock(&finlock)
	return old
}

func FinalizerGAsleep() bool {
	return fingStatus.Load()&fingWait != 0
}

// For GCTestMoveStackOnNextCall, it's important not to introduce an
// extra layer of call, since then there's a return before the "real"
// next call.
var GCTestMoveStackOnNextCall = gcTestMoveStackOnNextCall

// For GCTestIsReachable, it's important that we do this as a call so
// escape analysis can see through it.
func GCTestIsReachable(ptrs ...unsafe.Pointer) (mask uint64) {
	return gcTestIsReachable(ptrs...)
}

// For GCTestPointerClass, it's important that we do this as a call so
// escape analysis can see through it.
//
// This is nosplit because gcTestPointerClass is.
//
//go:nosplit
func GCTestPointerClass(p unsafe.Pointer) string {
	return gcTestPointerClass(p)
}

const Raceenabled = raceenabled

const (
	GCBackgroundUtilization            = gcBackgroundUtilization
	GCGoalUtilization                  = gcGoalUtilization
	DefaultHeapMinimum                 = defaultHeapMinimum
	MemoryLimitHeapGoalHeadroomPercent = memoryLimitHeapGoalHeadroomPercent
	MemoryLimitMinHeapGoalHeadroom     = memoryLimitMinHeapGoalHeadroom
)

type GCController struct {
	gcControllerState
}

func NewGCController(gcPercent int, memoryLimit int64) *GCController {
	// Force the controller to escape. We're going to
	// do 64-bit atomics on it, and if it gets stack-allocated
	// on a 32-bit architecture, it may get allocated unaligned
	// space.
	g := Escape(new(GCController))
	g.gcControllerState.test = true // Mark it as a test copy.
	g.init(int32(gcPercent), memoryLimit)
	return g
}

func (c *GCController) StartCycle(stackSize, globalsSize uint64, scannableFrac float64, gomaxprocs int) {
	trigger, _ := c.trigger()
	if c.heapMarked > trigger {
		trigger = c.heapMarked
	}
	c.maxStackScan.Store(stackSize)
	c.globalsScan.Store(globalsSize)
	c.heapLive.Store(trigger)
	c.heapScan.Add(int64(float64(trigger-c.heapMarked) * scannableFrac))
	c.startCycle(0, gomaxprocs, gcTrigger{kind: gcTriggerHeap})
}

func (c *GCController) AssistWorkPerByte() float64 {
	return c.assistWorkPerByte.Load()
}

func (c *GCController) HeapGoal() uint64 {
	return c.heapGoal()
}

func (c *GCController) HeapLive() uint64 {
	return c.heapLive.Load()
}

func (c *GCController) HeapMarked() uint64 {
	return c.heapMarked
}

func (c *GCController) Triggered() uint64 {
	return c.triggered
}

type GCControllerReviseDelta struct {
	HeapLive        int64
	HeapScan        int64
	HeapScanWork    int64
	StackScanWork   int64
	GlobalsScanWork int64
}

func (c *GCController) Revise(d GCControllerReviseDelta) {
	c.heapLive.Add(d.HeapLive)
	c.heapScan.Add(d.HeapScan)
	c.heapScanWork.Add(d.HeapScanWork)
	c.stackScanWork.Add(d.StackScanWork)
	c.globalsScanWork.Add(d.GlobalsScanWork)
	c.revise()
}

func (c *GCController) EndCycle(bytesMarked uint64, assistTime, elapsed int64, gomaxprocs int) {
	c.assistTime.Store(assistTime)
	c.endCycle(elapsed, gomaxprocs, false)
	c.resetLive(bytesMarked)
	c.commit(false)
}

func (c *GCController) AddIdleMarkWorker() bool {
	return c.addIdleMarkWorker()
}

func (c *GCController) NeedIdleMarkWorker() bool {
	return c.needIdleMarkWorker()
}

func (c *GCController) RemoveIdleMarkWorker() {
	c.removeIdleMarkWorker()
}

func (c *GCController) SetMaxIdleMarkWorkers(max int32) {
	c.setMaxIdleMarkWorkers(max)
}

var alwaysFalse bool
var escapeSink any

func Escape[T any](x T) T {
	if alwaysFalse {
		escapeSink = x
	}
	return x
}

// Acquirem blocks preemption.
func Acquirem() {
	acquirem()
}

func Releasem() {
	releasem(getg().m)
}

var Timediv = timediv

type PIController struct {
	piController
}

func NewPIController(kp, ti, tt, min, max float64) *PIController {
	return &PIController{piController{
		kp:  kp,
		ti:  ti,
		tt:  tt,
		min: min,
		max: max,
	}}
}

func (c *PIController) Next(input, setpoint, period float64) (float64, bool) {
	return c.piController.next(input, setpoint, period)
}

const (
	CapacityPerProc          = capacityPerProc
	GCCPULimiterUpdatePeriod = gcCPULimiterUpdatePeriod
)

type GCCPULimiter struct {
	limiter gcCPULimiterState
}

func NewGCCPULimiter(now int64, gomaxprocs int32) *GCCPULimiter {
	// Force the controller to escape. We're going to
	// do 64-bit atomics on it, and if it gets stack-allocated
	// on a 32-bit architecture, it may get allocated unaligned
	// space.
	l := Escape(new(GCCPULimiter))
	l.limiter.test = true
	l.limiter.resetCapacity(now, gomaxprocs)
	return l
}

func (l *GCCPULimiter) Fill() uint64 {
	return l.limiter.bucket.fill
}

func (l *GCCPULimiter) Capacity() uint64 {
	return l.limiter.bucket.capacity
}

func (l *GCCPULimiter) Overflow() uint64 {
	return l.limiter.overflow
}

func (l *GCCPULimiter) Limiting() bool {
	return l.limiter.limiting()
}

func (l *GCCPULimiter) NeedUpdate(now int64) bool {
	return l.limiter.needUpdate(now)
}

func (l *GCCPULimiter) StartGCTransition(enableGC bool, now int64) {
	l.limiter.startGCTransition(enableGC, now)
}

func (l *GCCPULimiter) FinishGCTransition(now int64) {
	l.limiter.finishGCTransition(now)
}

func (l *GCCPULimiter) Update(now int64) {
	l.limiter.update(now)
}

func (l *GCCPULimiter) AddAssistTime(t int64) {
	l.limiter.addAssistTime(t)
}

func (l *GCCPULimiter) ResetCapacity(now int64, nprocs int32) {
	l.limiter.resetCapacity(now, nprocs)
}

const ScavengePercent = scavengePercent

type Scavenger struct {
	Sleep      func(int64) int64
	Scavenge   func(uintptr) (uintptr, int64)
	ShouldStop func() bool
	GoMaxProcs func() int32

	released  atomic.Uintptr
	scavenger scavengerState
	stop      chan<- struct{}
	done      <-chan struct{}
}

func (s *Scavenger) Start() {
	if s.Sleep == nil || s.Scavenge == nil || s.ShouldStop == nil || s.GoMaxProcs == nil {
		panic("must populate all stubs")
	}

	// Install hooks.
	s.scavenger.sleepStub = s.Sleep
	s.scavenger.scavenge = s.Scavenge
	s.scavenger.shouldStop = s.ShouldStop
	s.scavenger.gomaxprocs = s.GoMaxProcs

	// Start up scavenger goroutine, and wait for it to be ready.
	stop := make(chan struct{})
	s.stop = stop
	done := make(chan struct{})
	s.done = done
	go func() {
		// This should match bgscavenge, loosely.
		s.scavenger.init()
		s.scavenger.park()
		for {
			select {
			case <-stop:
				close(done)
				return
			default:
			}
			released, workTime := s.scavenger.run()
			if released == 0 {
				s.scavenger.park()
				continue
			}
			s.released.Add(released)
			s.scavenger.sleep(workTime)
		}
	}()
	if !s.BlockUntilParked(1e9 /* 1 second */) {
		panic("timed out waiting for scavenger to get ready")
	}
}

// BlockUntilParked blocks until the scavenger parks, or until
// timeout is exceeded. Returns true if the scavenger parked.
//
// Note that in testing, parked means something slightly different.
// In anger, the scavenger parks to sleep, too, but in testing,
// it only parks when it actually has no work to do.
func (s *Scavenger) BlockUntilParked(timeout int64) bool {
	// Just spin, waiting for it to park.
	//
	// The actual parking process is racy with respect to
	// wakeups, which is fine, but for testing we need something
	// a bit more robust.
	start := nanotime()
	for nanotime()-start < timeout {
		lock(&s.scavenger.lock)
		parked := s.scavenger.parked
		unlock(&s.scavenger.lock)
		if parked {
			return true
		}
		Gosched()
	}
	return false
}

// Released returns how many bytes the scavenger released.
func (s *Scavenger) Released() uintptr {
	return s.released.Load()
}

// Wake wakes up a parked scavenger to keep running.
func (s *Scavenger) Wake() {
	s.scavenger.wake()
}

// Stop cleans up the scavenger's resources. The scavenger
// must be parked for this to work.
func (s *Scavenger) Stop() {
	lock(&s.scavenger.lock)
	parked := s.scavenger.parked
	unlock(&s.scavenger.lock)
	if !parked {
		panic("tried to clean up scavenger that is not parked")
	}
	close(s.stop)
	s.Wake()
	<-s.done
}

type ScavengeIndex struct {
	i scavengeIndex
}

func NewScavengeIndex(min, max ChunkIdx) *ScavengeIndex {
	s := new(ScavengeIndex)
	// This is a bit lazy but we easily guarantee we'll be able
	// to reference all the relevant chunks. The worst-case
	// memory usage here is 512 MiB, but tests generally use
	// small offsets from BaseChunkIdx, which results in ~100s
	// of KiB in memory use.
	//
	// This may still be worth making better, at least by sharing
	// this fairly large array across calls with a sync.Pool or
	// something. Currently, when the tests are run serially,
	// it takes around 0.5s. Not all that much, but if we have
	// a lot of tests like this it could add up.
	s.i.chunks = make([]atomicScavChunkData, max)
	s.i.min.Store(uintptr(min))
	s.i.max.Store(uintptr(max))
	s.i.minHeapIdx.Store(uintptr(min))
	s.i.test = true
	return s
}

func (s *ScavengeIndex) Find(force bool) (ChunkIdx, uint) {
	ci, off := s.i.find(force)
	return ChunkIdx(ci), off
}

func (s *ScavengeIndex) AllocRange(base, limit uintptr) {
	sc, ec := chunkIndex(base), chunkIndex(limit-1)
	si, ei := chunkPageIndex(base), chunkPageIndex(limit-1)

	if sc == ec {
		// The range doesn't cross any chunk boundaries.
		s.i.alloc(sc, ei+1-si)
	} else {
		// The range crosses at least one chunk boundary.
		s.i.alloc(sc, pallocChunkPages-si)
		for c := sc + 1; c < ec; c++ {
			s.i.alloc(c, pallocChunkPages)
		}
		s.i.alloc(ec, ei+1)
	}
}

func (s *ScavengeIndex) FreeRange(base, limit uintptr) {
	sc, ec := chunkIndex(base), chunkIndex(limit-1)
	si, ei := chunkPageIndex(base), chunkPageIndex(limit-1)

	if sc == ec {
		// The range doesn't cross any chunk boundaries.
		s.i.free(sc, si, ei+1-si)
	} else {
		// The range crosses at least one chunk boundary.
		s.i.free(sc, si, pallocChunkPages-si)
		for c := sc + 1; c < ec; c++ {
			s.i.free(c, 0, pallocChunkPages)
		}
		s.i.free(ec, 0, ei+1)
	}
}

func (s *ScavengeIndex) ResetSearchAddrs() {
	for _, a := range []*atomicOffAddr{&s.i.searchAddrBg, &s.i.searchAddrForce} {
		addr, marked := a.Load()
		if marked {
			a.StoreUnmark(addr, addr)
		}
		a.Clear()
	}
	s.i.freeHWM = minOffAddr
}

func (s *ScavengeIndex) NextGen() {
	s.i.nextGen()
}

func (s *ScavengeIndex) SetEmpty(ci ChunkIdx) {
	s.i.setEmpty(chunkIdx(ci))
}

func CheckPackScavChunkData(gen uint32, inUse, lastInUse uint16, flags uint8) bool {
	sc0 := scavChunkData{
		gen:            gen,
		inUse:          inUse,
		lastInUse:      lastInUse,
		scavChunkFlags: scavChunkFlags(flags),
	}
	scp := sc0.pack()
	sc1 := unpackScavChunkData(scp)
	return sc0 == sc1
}

const GTrackingPeriod = gTrackingPeriod

var ZeroBase = unsafe.Pointer(&zerobase)

const UserArenaChunkBytes = userArenaChunkBytes

type UserArena struct {
	arena *userArena
}

func NewUserArena() *UserArena {
	return &UserArena{newUserArena()}
}

func (a *UserArena) New(out *any) {
	i := efaceOf(out)
	typ := i._type
	if typ.Kind_&abi.KindMask != abi.Pointer {
		panic("new result of non-ptr type")
	}
	typ = (*ptrtype)(unsafe.Pointer(typ)).Elem
	i.data = a.arena.new(typ)
}

func (a *UserArena) Slice(sl any, cap int) {
	a.arena.slice(sl, cap)
}

func (a *UserArena) Free() {
	a.arena.free()
}

func GlobalWaitingArenaChunks() int {
	n := 0
	systemstack(func() {
		lock(&mheap_.lock)
		for s := mheap_.userArena.quarantineList.first; s != nil; s = s.next {
			n++
		}
		unlock(&mheap_.lock)
	})
	return n
}

func UserArenaClone[T any](s T) T {
	return arena_heapify(s).(T)
}

var AlignUp = alignUp

func BlockUntilEmptyFinalizerQueue(timeout int64) bool {
	return blockUntilEmptyFinalizerQueue(timeout)
}

func FrameStartLine(f *Frame) int {
	return f.startLine
}

// PersistentAlloc allocates some memory that lives outside the Go heap.
// This memory will never be freed; use sparingly.
func PersistentAlloc(n uintptr) unsafe.Pointer {
	return persistentalloc(n, 0, &memstats.other_sys)
}

// FPCallers works like Callers and uses frame pointer unwinding to populate
// pcBuf with the return addresses of the physical frames on the stack.
func FPCallers(pcBuf []uintptr) int {
	return fpTracebackPCs(unsafe.Pointer(getfp()), pcBuf)
}

const FramePointerEnabled = framepointer_enabled

var (
	IsPinned      = isPinned
	GetPinCounter = pinnerGetPinCounter
)

func SetPinnerLeakPanic(f func()) {
	pinnerLeakPanic = f
}
func GetPinnerLeakPanic() func() {
	return pinnerLeakPanic
}

var testUintptr uintptr

func MyGenericFunc[T any]() {
	systemstack(func() {
		testUintptr = 4
	})
}

func UnsafePoint(pc uintptr) bool {
	fi := findfunc(pc)
	v := pcdatavalue(fi, abi.PCDATA_UnsafePoint, pc)
	switch v {
	case abi.UnsafePointUnsafe:
		return true
	case abi.UnsafePointSafe:
		return false
	case abi.UnsafePointRestart1, abi.UnsafePointRestart2, abi.UnsafePointRestartAtEntry:
		// These are all interruptible, they just encode a nonstandard
		// way of recovering when interrupted.
		return false
	default:
		var buf [20]byte
		panic("invalid unsafe point code " + string(itoa(buf[:], uint64(v))))
	}
}

type TraceMap struct {
	traceMap
}

func (m *TraceMap) PutString(s string) (uint64, bool) {
	return m.traceMap.put(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)))
}

func (m *TraceMap) Reset() {
	m.traceMap.reset()
}

func SetSpinInGCMarkDone(spin bool) {
	gcDebugMarkDone.spinAfterRaggedBarrier.Store(spin)
}

func GCMarkDoneRestarted() bool {
	// Only read this outside of the GC. If we're running during a GC, just report false.
	mp := acquirem()
	if gcphase != _GCoff {
		releasem(mp)
		return false
	}
	restarted := gcDebugMarkDone.restartedDueTo27993
	releasem(mp)
	return restarted
}

func GCMarkDoneResetRestartFlag() {
	mp := acquirem()
	for gcphase != _GCoff {
		releasem(mp)
		Gosched()
		mp = acquirem()
	}
	gcDebugMarkDone.restartedDueTo27993 = false
	releasem(mp)
}

type BitCursor struct {
	b bitCursor
}

func NewBitCursor(buf *byte) BitCursor {
	return BitCursor{b: bitCursor{ptr: buf, n: 0}}
}

func (b BitCursor) Write(data *byte, cnt uintptr) {
	b.b.write(data, cnt)
}
func (b BitCursor) Offset(cnt uintptr) BitCursor {
	return BitCursor{b: b.b.offset(cnt)}
}

"""




```