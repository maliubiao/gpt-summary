Response:
Let's break down the thought process for answering the request about `sigtab_aix.go`.

**1. Understanding the Goal:**

The core request is to understand the functionality of the provided Go code snippet, which defines a `sigtable` variable. The prompt specifically asks about its purpose within the Go runtime, how it's used, potential errors, and to provide a Go code example demonstrating its use.

**2. Initial Analysis of the Code:**

* **Filename:** `sigtab_aix.go` strongly suggests this file is specific to the AIX operating system. The `sigtab` part hints at a signal table.
* **Package:** `package runtime` confirms this is part of the Go runtime library, dealing with low-level operating system interactions.
* **Variable:** `var sigtable = [...]sigTabT{ ... }` declares a global variable named `sigtable`. The `[...]` syntax indicates an array whose size is determined by the initializer. The type `sigTabT` is crucial.
* **Data Structure:** The initializer is a large list of struct literals. Each struct has two fields: an integer and a string. The integer seems to be a bitmask or combination of flags (like `_SigNotify + _SigKill`). The string is a descriptive name of a signal.
* **Signal Constants:** The presence of constants like `_SIGHUP`, `_SIGINT`, etc., strongly indicates this table maps signal numbers to their properties. The prefix `_SIG` suggests internal runtime constants.
* **Flag Constants:** The constants like `_SigNotify`, `_SigKill`, `_SigThrow`, `_SigPanic`, `_SigUnblock`, and `_SigDefault` likely define how the Go runtime should handle each signal.

**3. Deductions and Hypotheses:**

Based on the initial analysis, several hypotheses emerge:

* **Signal Handling:** This table defines how the Go runtime handles different operating system signals on AIX.
* **Signal Properties:** The integer value in each struct likely represents a set of flags controlling the runtime's behavior when that signal is received.
* **Platform Specificity:**  The `_aix.go` suffix confirms this is platform-specific signal handling. Other operating systems will have their own `sigtab_*.go` files.
* **Internal Use:**  As part of the `runtime` package, this table is likely used internally by the Go runtime and not directly accessed by typical Go user code.

**4. Connecting to Go's Signal Handling Mechanism:**

The next step is to connect this low-level table to the higher-level signal handling mechanisms in Go that developers use. This involves considering the `os/signal` package.

* **`os/signal.Notify`:** This function is the primary way Go programs register to receive signals.
* **Signal Types:** The `os/signal` package uses `os.Signal` as the type representing signals. The underlying integer values likely correspond to the indices in the `sigtable`.

**5. Constructing the Explanation:**

Now, it's time to structure the answer logically:

* **Functionality:**  Start by clearly stating the primary function: defining how the Go runtime handles OS signals on AIX.
* **Structure:** Describe the `sigtable` variable, its type (`sigTabT`), and the meaning of its fields (signal number, flags, description).
* **Signal Handling Logic:** Explain the meaning of the flag constants (`_SigNotify`, etc.) and how they determine the runtime's response. Provide examples of different flag combinations and their effects.
* **Connecting to User-Level Code:** Explain how this internal table relates to the `os/signal` package. Show a Go code example using `signal.Notify` to catch signals. This demonstrates the *purpose* of the `sigtable` even though user code doesn't directly interact with it.
* **Code Example (Crucial):**  Create a simple, illustrative Go program that catches a signal (e.g., `syscall.SIGINT`) and prints a message. This makes the explanation concrete. Include assumed input (sending the signal) and the expected output.
* **Command-Line Arguments (Not Applicable):** The `sigtab_aix.go` file itself doesn't involve command-line argument processing. So, state this explicitly.
* **Potential Mistakes (Important):**  Think about common errors developers make when dealing with signals:
    * **Not handling signals:**  A program might terminate unexpectedly if it doesn't handle signals like `SIGINT` or `SIGTERM` gracefully.
    * **Incorrect signal handling:** Performing non-reentrant operations within signal handlers can lead to deadlocks or undefined behavior. Emphasize the importance of keeping signal handlers minimal.
    * **Platform differences:**  Highlight that signal numbers and behavior can vary across operating systems, and `sigtab_aix.go` is specific to AIX.
* **Language:** Use clear and concise Chinese, as requested.

**6. Refinement and Review:**

After drafting the answer, review it for clarity, accuracy, and completeness. Ensure the Go code example is correct and the explanation is easy to understand. Check if all parts of the prompt have been addressed. For instance, double-check the meaning of each flag constant based on common signal handling semantics.

This structured approach, starting with code analysis and gradually connecting it to higher-level concepts and potential pitfalls, leads to a comprehensive and helpful answer. The key is to understand the *why* behind the code, not just the *what*.
这段 `go/src/runtime/sigtab_aix.go` 文件是 Go 运行时环境（runtime）中用于定义在 AIX 操作系统上信号处理方式的一部分。它主要包含一个名为 `sigtable` 的数组，这个数组的每个元素描述了一个特定信号的行为。

**主要功能:**

1. **定义信号处理策略:** `sigtable` 数组中的每个 `sigTabT` 结构体定义了当 Go 程序接收到特定信号时，运行时系统应该采取的行动。这些行动包括：
    * **_SigNotify:**  表示该信号应该被传递给 Go 程序的用户代码，可以通过 `os/signal` 包来捕获和处理。
    * **_SigKill:**  表示接收到该信号应该终止程序。
    * **_SigThrow:** 表示接收到该信号应该抛出一个 Go 语言的 panic。
    * **_SigPanic:**  与 `_SigThrow` 类似，也表示抛出 panic。可能在内部处理上略有不同，或者在不同的上下文中使用。
    * **_SigUnblock:** 表示应该取消对该信号的阻塞。
    * **_SigDefault:** 表示应该执行该信号的默认操作系统行为。

2. **关联信号编号和行为:**  `sigtable` 数组使用信号的编号作为索引（例如 `_SIGHUP`、`_SIGINT` 等），将特定的信号与预定义的处理行为关联起来。例如，`_SIGINT` (通常是 Ctrl+C 产生的信号) 被设置为 `_SigNotify + _SigKill`，这意味着 Go 程序可以捕获这个信号，但如果程序没有处理，运行时系统最终会终止程序。

3. **平台特定性:**  `sigtab_aix.go` 文件名中的 `_aix` 表明这个文件是专门为 AIX 操作系统定制的。不同的操作系统可能有不同的信号集和默认行为，因此 Go 运行时需要针对每个平台进行适配。

**推理出的 Go 语言功能实现：信号处理**

`sigtab_aix.go` 是 Go 语言信号处理机制的核心组成部分。当操作系统向 Go 程序发送一个信号时，运行时系统会查找 `sigtable` 数组中对应信号的处理方式，并根据定义执行相应的操作。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 创建一个接收信号的通道
	sigs := make(chan os.Signal, 1)

	// 注册要接收的信号 (这里以 SIGINT 为例)
	signal.Notify(sigs, syscall.SIGINT)

	// 启动一个 goroutine 来监听信号
	go func() {
		sig := <-sigs
		fmt.Println("\n接收到信号:", sig)
		// 在接收到 SIGINT 后进行一些清理工作或者优雅退出
		fmt.Println("程序即将退出...")
		os.Exit(0)
	}()

	fmt.Println("程序正在运行，请按 Ctrl+C 发送 SIGINT 信号")

	// 模拟程序运行
	for i := 0; ; i++ {
		fmt.Print(".")
		// 模拟一些工作
		// time.Sleep(time.Second)
	}
}
```

**假设的输入与输出:**

**输入:** 用户在终端中运行上述 Go 程序，并在程序运行时按下 `Ctrl+C` 组合键。这会向程序发送一个 `SIGINT` 信号。

**输出:**

```
程序正在运行，请按 Ctrl+C 发送 SIGINT 信号
................
接收到信号: interrupt
程序即将退出...
```

**代码推理:**

1. **`signal.Notify(sigs, syscall.SIGINT)`:**  这行代码指示 Go 运行时，当接收到 `syscall.SIGINT` 信号时，将该信号发送到 `sigs` 通道。
2. **`go func() { ... }()`:**  启动了一个新的 goroutine，专门用来监听 `sigs` 通道。
3. **`sig := <-sigs`:**  这个 goroutine 会阻塞在这里，直到 `sigs` 通道接收到一个信号。
4. **`fmt.Println("\n接收到信号:", sig)`:** 当接收到 `SIGINT` 信号时，会打印出接收到的信号信息。
5. **`os.Exit(0)`:**  程序执行退出操作。

**sigtable 的作用:**

在上述例子中，当我们调用 `signal.Notify(sigs, syscall.SIGINT)` 时，Go 运行时会查看 `sigtab_aix.go` 中的 `sigtable`，找到 `_SIGINT` 对应的条目 `{_SigNotify + _SigKill, "SIGINT: interrupt"}`。`_SigNotify` 告诉运行时，这个信号应该被传递给用户代码通过 `signal.Notify` 注册的通道。

如果没有调用 `signal.Notify`，并且程序接收到 `SIGINT`，那么 `_SigKill` 标志会起作用，导致运行时直接终止程序。

**命令行参数:**

`sigtab_aix.go` 文件本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数或者使用 `flag` 包等进行解析。 `sigtab_aix.go` 是 Go 运行时内部使用的，用于配置信号处理行为。

**使用者易犯错的点:**

1. **没有处理某些需要优雅退出的信号:**  开发者可能只关注程序的主要逻辑，而忽略了对诸如 `SIGINT` 或 `SIGTERM` 信号的处理。这会导致程序在接收到这些信号时直接被操作系统强行终止，可能导致数据丢失或状态不一致。

   **错误示例:**

   ```go
   package main

   import (
       "fmt"
       "time"
   )

   func main() {
       fmt.Println("程序正在运行...")
       for {
           fmt.Println("执行任务...")
           time.Sleep(1 * time.Second)
       }
   }
   ```

   在这个例子中，如果用户按下 `Ctrl+C`，程序会立即被终止，没有任何清理操作。

2. **在信号处理函数中执行不安全的操作:**  信号处理函数应该尽可能简洁，避免执行可能导致死锁或竞态条件的操作。例如，在信号处理函数中尝试获取互斥锁可能会导致问题，因为程序可能在持有锁的状态下接收到信号。

   **说明:**  Go 的运行时系统会在接收到信号时暂停当前 goroutine 的执行，并运行信号处理函数。如果信号处理函数尝试访问被暂停的 goroutine 正在使用的资源，就可能发生问题。

总之，`go/src/runtime/sigtab_aix.go` 是 Go 运行时在 AIX 操作系统上进行信号处理的关键配置，它定义了不同信号的默认行为，并与 Go 语言提供的 `os/signal` 包协同工作，允许开发者自定义信号处理逻辑。理解这个文件的作用有助于开发者更好地理解和处理 Go 程序的信号机制。

### 提示词
```
这是路径为go/src/runtime/sigtab_aix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

var sigtable = [...]sigTabT{
	0:           {0, "SIGNONE: no trap"},
	_SIGHUP:     {_SigNotify + _SigKill, "SIGHUP: terminal line hangup"},
	_SIGINT:     {_SigNotify + _SigKill, "SIGINT: interrupt"},
	_SIGQUIT:    {_SigNotify + _SigThrow, "SIGQUIT: quit"},
	_SIGILL:     {_SigThrow + _SigUnblock, "SIGILL: illegal instruction"},
	_SIGTRAP:    {_SigThrow + _SigUnblock, "SIGTRAP: trace trap"},
	_SIGABRT:    {_SigNotify + _SigThrow, "SIGABRT: abort"},
	_SIGBUS:     {_SigPanic + _SigUnblock, "SIGBUS: bus error"},
	_SIGFPE:     {_SigPanic + _SigUnblock, "SIGFPE: floating-point exception"},
	_SIGKILL:    {0, "SIGKILL: kill"},
	_SIGUSR1:    {_SigNotify, "SIGUSR1: user-defined signal 1"},
	_SIGSEGV:    {_SigPanic + _SigUnblock, "SIGSEGV: segmentation violation"},
	_SIGUSR2:    {_SigNotify, "SIGUSR2: user-defined signal 2"},
	_SIGPIPE:    {_SigNotify, "SIGPIPE: write to broken pipe"},
	_SIGALRM:    {_SigNotify, "SIGALRM: alarm clock"},
	_SIGTERM:    {_SigNotify + _SigKill, "SIGTERM: termination"},
	_SIGCHLD:    {_SigNotify + _SigUnblock, "SIGCHLD: child status has changed"},
	_SIGCONT:    {_SigNotify + _SigDefault, "SIGCONT: continue"},
	_SIGSTOP:    {0, "SIGSTOP: stop"},
	_SIGTSTP:    {_SigNotify + _SigDefault, "SIGTSTP: keyboard stop"},
	_SIGTTIN:    {_SigNotify + _SigDefault, "SIGTTIN: background read from tty"},
	_SIGTTOU:    {_SigNotify + _SigDefault, "SIGTTOU: background write to tty"},
	_SIGURG:     {_SigNotify, "SIGURG: urgent condition on socket"},
	_SIGXCPU:    {_SigNotify, "SIGXCPU: cpu limit exceeded"},
	_SIGXFSZ:    {_SigNotify, "SIGXFSZ: file size limit exceeded"},
	_SIGVTALRM:  {_SigNotify, "SIGVTALRM: virtual alarm clock"},
	_SIGPROF:    {_SigNotify + _SigUnblock, "SIGPROF: profiling alarm clock"},
	_SIGWINCH:   {_SigNotify, "SIGWINCH: window size change"},
	_SIGSYS:     {_SigThrow, "SIGSYS: bad system call"},
	_SIGIO:      {_SigNotify, "SIGIO: i/o now possible"},
	_SIGPWR:     {_SigNotify, "SIGPWR: power failure restart"},
	_SIGEMT:     {_SigThrow, "SIGEMT: emulate instruction executed"},
	_SIGWAITING: {0, "SIGWAITING: reserved signal no longer used by"},
	26:          {_SigNotify, "signal 26"},
	27:          {_SigNotify, "signal 27"},
	33:          {_SigNotify, "signal 33"},
	35:          {_SigNotify, "signal 35"},
	36:          {_SigNotify, "signal 36"},
	37:          {_SigNotify, "signal 37"},
	38:          {_SigNotify, "signal 38"},
	40:          {_SigNotify, "signal 40"},
	41:          {_SigNotify, "signal 41"},
	42:          {_SigNotify, "signal 42"},
	43:          {_SigNotify, "signal 43"},
	44:          {_SigNotify, "signal 44"},
	45:          {_SigNotify, "signal 45"},
	46:          {_SigNotify, "signal 46"},
	47:          {_SigNotify, "signal 47"},
	48:          {_SigNotify, "signal 48"},
	49:          {_SigNotify, "signal 49"},
	50:          {_SigNotify, "signal 50"},
	51:          {_SigNotify, "signal 51"},
	52:          {_SigNotify, "signal 52"},
	53:          {_SigNotify, "signal 53"},
	54:          {_SigNotify, "signal 54"},
	55:          {_SigNotify, "signal 55"},
	56:          {_SigNotify, "signal 56"},
	57:          {_SigNotify, "signal 57"},
	58:          {_SigNotify, "signal 58"},
	59:          {_SigNotify, "signal 59"},
	60:          {_SigNotify, "signal 60"},
	61:          {_SigNotify, "signal 61"},
	62:          {_SigNotify, "signal 62"},
	63:          {_SigNotify, "signal 63"},
	64:          {_SigNotify, "signal 64"},
	65:          {_SigNotify, "signal 65"},
	66:          {_SigNotify, "signal 66"},
	67:          {_SigNotify, "signal 67"},
	68:          {_SigNotify, "signal 68"},
	69:          {_SigNotify, "signal 69"},
	70:          {_SigNotify, "signal 70"},
	71:          {_SigNotify, "signal 71"},
	72:          {_SigNotify, "signal 72"},
	73:          {_SigNotify, "signal 73"},
	74:          {_SigNotify, "signal 74"},
	75:          {_SigNotify, "signal 75"},
	76:          {_SigNotify, "signal 76"},
	77:          {_SigNotify, "signal 77"},
	78:          {_SigNotify, "signal 78"},
	79:          {_SigNotify, "signal 79"},
	80:          {_SigNotify, "signal 80"},
	81:          {_SigNotify, "signal 81"},
	82:          {_SigNotify, "signal 82"},
	83:          {_SigNotify, "signal 83"},
	84:          {_SigNotify, "signal 84"},
	85:          {_SigNotify, "signal 85"},
	86:          {_SigNotify, "signal 86"},
	87:          {_SigNotify, "signal 87"},
	88:          {_SigNotify, "signal 88"},
	89:          {_SigNotify, "signal 89"},
	90:          {_SigNotify, "signal 90"},
	91:          {_SigNotify, "signal 91"},
	92:          {_SigNotify, "signal 92"},
	93:          {_SigNotify, "signal 93"},
	94:          {_SigNotify, "signal 94"},
	95:          {_SigNotify, "signal 95"},
	96:          {_SigNotify, "signal 96"},
	97:          {_SigNotify, "signal 97"},
	98:          {_SigNotify, "signal 98"},
	99:          {_SigNotify, "signal 99"},
	100:         {_SigNotify, "signal 100"},
	101:         {_SigNotify, "signal 101"},
	102:         {_SigNotify, "signal 102"},
	103:         {_SigNotify, "signal 103"},
	104:         {_SigNotify, "signal 104"},
	105:         {_SigNotify, "signal 105"},
	106:         {_SigNotify, "signal 106"},
	107:         {_SigNotify, "signal 107"},
	108:         {_SigNotify, "signal 108"},
	109:         {_SigNotify, "signal 109"},
	110:         {_SigNotify, "signal 110"},
	111:         {_SigNotify, "signal 111"},
	112:         {_SigNotify, "signal 112"},
	113:         {_SigNotify, "signal 113"},
	114:         {_SigNotify, "signal 114"},
	115:         {_SigNotify, "signal 115"},
	116:         {_SigNotify, "signal 116"},
	117:         {_SigNotify, "signal 117"},
	118:         {_SigNotify, "signal 118"},
	119:         {_SigNotify, "signal 119"},
	120:         {_SigNotify, "signal 120"},
	121:         {_SigNotify, "signal 121"},
	122:         {_SigNotify, "signal 122"},
	123:         {_SigNotify, "signal 123"},
	124:         {_SigNotify, "signal 124"},
	125:         {_SigNotify, "signal 125"},
	126:         {_SigNotify, "signal 126"},
	127:         {_SigNotify, "signal 127"},
	128:         {_SigNotify, "signal 128"},
	129:         {_SigNotify, "signal 129"},
	130:         {_SigNotify, "signal 130"},
	131:         {_SigNotify, "signal 131"},
	132:         {_SigNotify, "signal 132"},
	133:         {_SigNotify, "signal 133"},
	134:         {_SigNotify, "signal 134"},
	135:         {_SigNotify, "signal 135"},
	136:         {_SigNotify, "signal 136"},
	137:         {_SigNotify, "signal 137"},
	138:         {_SigNotify, "signal 138"},
	139:         {_SigNotify, "signal 139"},
	140:         {_SigNotify, "signal 140"},
	141:         {_SigNotify, "signal 141"},
	142:         {_SigNotify, "signal 142"},
	143:         {_SigNotify, "signal 143"},
	144:         {_SigNotify, "signal 144"},
	145:         {_SigNotify, "signal 145"},
	146:         {_SigNotify, "signal 146"},
	147:         {_SigNotify, "signal 147"},
	148:         {_SigNotify, "signal 148"},
	149:         {_SigNotify, "signal 149"},
	150:         {_SigNotify, "signal 150"},
	151:         {_SigNotify, "signal 151"},
	152:         {_SigNotify, "signal 152"},
	153:         {_SigNotify, "signal 153"},
	154:         {_SigNotify, "signal 154"},
	155:         {_SigNotify, "signal 155"},
	156:         {_SigNotify, "signal 156"},
	157:         {_SigNotify, "signal 157"},
	158:         {_SigNotify, "signal 158"},
	159:         {_SigNotify, "signal 159"},
	160:         {_SigNotify, "signal 160"},
	161:         {_SigNotify, "signal 161"},
	162:         {_SigNotify, "signal 162"},
	163:         {_SigNotify, "signal 163"},
	164:         {_SigNotify, "signal 164"},
	165:         {_SigNotify, "signal 165"},
	166:         {_SigNotify, "signal 166"},
	167:         {_SigNotify, "signal 167"},
	168:         {_SigNotify, "signal 168"},
	169:         {_SigNotify, "signal 169"},
	170:         {_SigNotify, "signal 170"},
	171:         {_SigNotify, "signal 171"},
	172:         {_SigNotify, "signal 172"},
	173:         {_SigNotify, "signal 173"},
	174:         {_SigNotify, "signal 174"},
	175:         {_SigNotify, "signal 175"},
	176:         {_SigNotify, "signal 176"},
	177:         {_SigNotify, "signal 177"},
	178:         {_SigNotify, "signal 178"},
	179:         {_SigNotify, "signal 179"},
	180:         {_SigNotify, "signal 180"},
	181:         {_SigNotify, "signal 181"},
	182:         {_SigNotify, "signal 182"},
	183:         {_SigNotify, "signal 183"},
	184:         {_SigNotify, "signal 184"},
	185:         {_SigNotify, "signal 185"},
	186:         {_SigNotify, "signal 186"},
	187:         {_SigNotify, "signal 187"},
	188:         {_SigNotify, "signal 188"},
	189:         {_SigNotify, "signal 189"},
	190:         {_SigNotify, "signal 190"},
	191:         {_SigNotify, "signal 191"},
	192:         {_SigNotify, "signal 192"},
	193:         {_SigNotify, "signal 193"},
	194:         {_SigNotify, "signal 194"},
	195:         {_SigNotify, "signal 195"},
	196:         {_SigNotify, "signal 196"},
	197:         {_SigNotify, "signal 197"},
	198:         {_SigNotify, "signal 198"},
	199:         {_SigNotify, "signal 199"},
	200:         {_SigNotify, "signal 200"},
	201:         {_SigNotify, "signal 201"},
	202:         {_SigNotify, "signal 202"},
	203:         {_SigNotify, "signal 203"},
	204:         {_SigNotify, "signal 204"},
	205:         {_SigNotify, "signal 205"},
	206:         {_SigNotify, "signal 206"},
	207:         {_SigNotify, "signal 207"},
	208:         {_SigNotify, "signal 208"},
	209:         {_SigNotify, "signal 209"},
	210:         {_SigNotify, "signal 210"},
	211:         {_SigNotify, "signal 211"},
	212:         {_SigNotify, "signal 212"},
	213:         {_SigNotify, "signal 213"},
	214:         {_SigNotify, "signal 214"},
	215:         {_SigNotify, "signal 215"},
	216:         {_SigNotify, "signal 216"},
	217:         {_SigNotify, "signal 217"},
	218:         {_SigNotify, "signal 218"},
	219:         {_SigNotify, "signal 219"},
	220:         {_SigNotify, "signal 220"},
	221:         {_SigNotify, "signal 221"},
	222:         {_SigNotify, "signal 222"},
	223:         {_SigNotify, "signal 223"},
	224:         {_SigNotify, "signal 224"},
	225:         {_SigNotify, "signal 225"},
	226:         {_SigNotify, "signal 226"},
	227:         {_SigNotify, "signal 227"},
	228:         {_SigNotify, "signal 228"},
	229:         {_SigNotify, "signal 229"},
	230:         {_SigNotify, "signal 230"},
	231:         {_SigNotify, "signal 231"},
	232:         {_SigNotify, "signal 232"},
	233:         {_SigNotify, "signal 233"},
	234:         {_SigNotify, "signal 234"},
	235:         {_SigNotify, "signal 235"},
	236:         {_SigNotify, "signal 236"},
	237:         {_SigNotify, "signal 237"},
	238:         {_SigNotify, "signal 238"},
	239:         {_SigNotify, "signal 239"},
	240:         {_SigNotify, "signal 240"},
	241:         {_SigNotify, "signal 241"},
	242:         {_SigNotify, "signal 242"},
	243:         {_SigNotify, "signal 243"},
	244:         {_SigNotify, "signal 244"},
	245:         {_SigNotify, "signal 245"},
	246:         {_SigNotify, "signal 246"},
	247:         {_SigNotify, "signal 247"},
	248:         {_SigNotify, "signal 248"},
	249:         {_SigNotify, "signal 249"},
	250:         {_SigNotify, "signal 250"},
	251:         {_SigNotify, "signal 251"},
	252:         {_SigNotify, "signal 252"},
	253:         {_SigNotify, "signal 253"},
	254:         {_SigNotify, "signal 254"},
	255:         {_SigNotify, "signal 255"},
}
```