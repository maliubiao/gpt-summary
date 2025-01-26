Response:
我的思考过程如下：

1. **理解目标:** 目标是分析一个 Go 语言的 `acme` 包的实现，并从功能、使用方式、潜在错误等方面进行总结。需要结合代码进行推断和举例。

2. **识别核心概念:**  快速浏览代码，发现关键类型 `Win` 和 `Event`。  `Win` 代表一个 acme 编辑器窗口，而 `Event` 代表窗口中发生的操作。  还有一些辅助类型如 `LogReader` 和 `LogEvent`，用于读取 acme 的日志。

3. **梳理主要功能:** 逐个函数阅读，理解其用途。我将函数大致归类如下：
    * **窗口管理:** `New`, `Open`, `Windows`, `Show`, `Del`, `DeleteAll`, `CloseFiles`, `drop`, `dropLocked`. 这些函数负责创建、打开、列出、显示、删除和关闭 acme 窗口。
    * **文件访问:** `fid`, `ReadAll`, `Read`, `Write`, `Fprintf`, `Seek`. 这些函数提供了访问 acme 窗口内部的各个文件（ctl, tag, body, addr, event, data, xdata, errors）的能力。
    * **内容操作:** `Addr`, `Name`, `Clear`, `PrintTabbed`, `Sort`. 这些函数用于操作窗口的内容，例如设置地址范围、设置窗口名称、清空内容、格式化打印和排序。
    * **事件处理:** `ReadEvent`, `WriteEvent`, `EventChan`, `eventReader`, `EventLoop`. 这些函数用于读取和写入 acme 窗口的事件，实现与 acme 编辑器的交互。
    * **其他:**  `Log`, `Font`, `Blink`, `Selection`, `SetErrorPrefix`, `Err`. 这些函数提供日志读取、字体信息获取、标签闪烁、获取选中文本和错误处理等功能。

4. **推断 Go 语言功能:** 基于对函数功能的理解，我开始推断其背后的 Go 语言功能：
    * **与 Plan 9 交互:** 导入了 `9fans.net/go/plan9` 和 `9fans.net/go/plan9/client` 包，这表明该包旨在与 Plan 9 操作系统及其服务进行交互。`client.MountService("acme")`  更是直接表明了与名为 "acme" 的服务进行交互。
    * **文件系统抽象:**  通过 `client.Fsys` 和 `client.Fid` 操作 acme 窗口的 "文件"，这是一种将 acme 窗口的各个方面抽象为文件的方式。
    * **并发:** 使用 `sync.Mutex` 进行互斥锁保护，使用 goroutine 和 channel (`EventChan`) 处理事件，表明该包考虑了并发安全性。
    * **字符串处理:**  大量使用 `strings` 包进行字符串分割、修剪等操作。
    * **类型转换:** 使用 `strconv` 包进行字符串和数字之间的转换。
    * **错误处理:**  函数通常返回 `error` 类型，表明有明确的错误处理机制。
    * **格式化:** 使用 `fmt.Sprintf` 进行格式化字符串的操作。
    * **IO 操作:** 使用 `io/ioutil` 和 `bufio` 包进行输入输出操作。

5. **代码举例:**  为关键功能编写示例代码：
    * **创建新窗口并写入内容:** 展示了 `New`, `Name`, 和 `Fprintf` 的用法。
    * **读取窗口内容:** 展示了 `Open`, `ReadAll` 和 `CloseFiles` 的用法。
    * **监听事件:** 展示了 `Open`, `EventChan` 和 `ReadEvent` 的用法。

6. **代码推理 (假设输入/输出):**  选择一些需要深入理解的函数进行推理：
    * **`ReadAddr()`:** 假设 `addr` 文件内容为 "10 20"，则 `ReadAddr()` 返回 `q0 = 10`, `q1 = 20`, `err = nil`。
    * **`ReadEvent()`:**  虽然直接模拟完整的事件数据比较复杂，但我解释了 `ReadEvent` 如何读取不同部分的事件信息，以及如何处理扩展和 chorded 参数。

7. **命令行参数处理:**  仔细检查代码，没有发现直接处理命令行参数的地方。 `acme` 服务本身可能通过其他方式启动和配置，这个 Go 包只是作为客户端与之交互。

8. **易犯错的点:**  考虑用户在使用该包时可能遇到的问题：
    * **忘记关闭文件:**  强调需要调用 `CloseFiles` 或 `Del` 来释放资源。
    * **并发访问问题:**  强调了 `EventChan` 的使用方式，以及避免在调用 `EventChan` 后直接调用 `ReadEvent`。
    * **事件处理不当:** 解释了 `WriteEvent` 的用途，以及在 `EventLoop` 中不处理事件时需要调用 `WriteEvent` 将事件传递回 acme。

9. **组织答案:** 将以上分析结果组织成结构清晰的中文答案，包括功能列表、Go 语言功能推断、代码示例、代码推理、命令行参数处理和易犯错的点。  使用清晰的标题和代码块，方便阅读。

通过以上步骤，我能够系统地分析给定的 Go 代码，并生成一个全面的解释。  关键在于理解代码背后的意图，以及如何将这些代码与 Go 语言的特性联系起来。  逐步分解问题，从宏观到微观地分析代码，并结合实际使用场景进行思考，是完成此类任务的关键。


这个Go语言实现的目的是提供一个简单接口，用于与Plan 9操作系统上的acme编辑器进行交互。acme是一个程序员的文本编辑器和shell集成环境。

以下是该代码的主要功能：

**1. 窗口管理:**

* **创建新窗口 (`New`)**: 允许程序创建一个新的acme窗口。
   ```go
   package main

   import (
       "fmt"
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       defer win.Del(true) // 确保程序退出时删除窗口

       fmt.Printf("创建了新的acme窗口，ID为: %d\n", win.ID())
   }
   ```
   **假设输出:**  创建了一个新的acme窗口，屏幕上会显示一个新的编辑器窗口，控制台输出类似于 `创建了新的acme窗口，ID为: 1` (ID可能不同)。

* **打开已存在的窗口 (`Open`)**:  可以连接到已存在的acme窗口，通过窗口的ID或者一个已有的控制文件描述符。
   ```go
   package main

   import (
       "fmt"
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       // 假设我们知道要打开的窗口ID是 1
       win, err := acme.Open(1, nil)
       if err != nil {
           log.Fatal(err)
       }
       defer win.CloseFiles()

       fmt.Printf("连接到acme窗口，ID为: %d\n", win.ID())
   }
   ```
   **假设输出:** 如果存在ID为1的acme窗口，则会连接到该窗口，控制台输出 `连接到acme窗口，ID为: 1`。

* **获取所有窗口信息 (`Windows`)**:  返回当前所有acme窗口的ID和名称。
   ```go
   package main

   import (
       "fmt"
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       windows, err := acme.Windows()
       if err != nil {
           log.Fatal(err)
       }
       fmt.Println("当前acme窗口:")
       for _, winInfo := range windows {
           fmt.Printf("ID: %d, Name: %s\n", winInfo.ID, winInfo.Name)
       }
   }
   ```
   **假设输出:**  列出当前所有打开的acme窗口的信息，例如：
   ```
   当前acme窗口:
   ID: 1, Name: /tmp/file.txt
   ID: 2, Name: +Errors
   ```

* **显示特定名称的窗口 (`Show`)**:  查找并显示具有特定名称的窗口。
   ```go
   package main

   import (
       "fmt"
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       win := acme.Show("+Errors")
       if win != nil {
           fmt.Println("找到了+Errors窗口")
           win.CloseFiles()
       } else {
           fmt.Println("未找到+Errors窗口")
       }
   }
   ```
   **假设输出:** 如果存在名为 "+Errors" 的窗口，则会显示该窗口并在控制台输出 `找到了+Errors窗口`。

* **删除窗口 (`Del`)**:  删除一个acme窗口。可以传递一个布尔值来决定是否发送 "delete" 命令（更强制的删除）。
   ```go
   package main

   import (
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       err = win.Del(true) // 强制删除
       if err != nil {
           log.Println("删除窗口时出错:", err)
       } else {
           log.Println("窗口已删除")
       }
   }
   ```
   **假设输出:** 创建的窗口会被删除，控制台输出 `窗口已删除`。

* **删除所有窗口 (`DeleteAll`)**:  关闭所有打开的acme窗口。

**2. 文件访问和操作 (acme窗口内部的文件):**

acme的每个窗口都有一组控制文件，该包提供了访问这些文件的能力：

* **`ctl`**:  用于发送控制命令到窗口。 (`Ctl`)
   ```go
   package main

   import (
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       defer win.Del(true)

       err = win.Ctl("name NewFileName") // 设置窗口名称
       if err != nil {
           log.Println("设置窗口名称失败:", err)
       }
   }
   ```
   **假设输出:** 创建的窗口的标题栏会显示 "NewFileName"。

* **`tag`**:  窗口的标签行。
* **`body`**:  窗口的主要内容。 (`Fprintf`, `Write`, `ReadAll`, `Clear`, `PrintTabbed`)
   ```go
   package main

   import (
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       defer win.Del(true)

       _, err = win.Fprintf("body", "Hello, acme!\n")
       if err != nil {
           log.Println("写入窗口内容失败:", err)
       }
   }
   ```
   **假设输出:** 创建的窗口中会显示 "Hello, acme!"。

* **`addr`**:  当前窗口的地址范围。 (`Addr`, `ReadAddr`)
   ```go
   package main

   import (
       "fmt"
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       defer win.Del(true)

       err = win.Fprintf("body", "line1\nline2\nline3\n")
       if err != nil {
           log.Println("写入窗口内容失败:", err)
       }

       err = win.Addr("#0") // 将地址设置为行首
       if err != nil {
           log.Println("设置地址失败:", err)
       }

       q0, q1, err := win.ReadAddr()
       if err != nil {
           log.Println("读取地址失败:", err)
       }
       fmt.Printf("当前地址范围: %d - %d\n", q0, q1)
   }
   ```
   **假设输出:**  控制台输出类似于 `当前地址范围: 0 - 0` （具体值取决于acme的内部状态）。

* **`event`**:  用于读取和写入窗口事件。 (`ReadEvent`, `WriteEvent`, `EventChan`, `EventLoop`)
   ```go
   package main

   import (
       "fmt"
       "log"
       "time"

       "9fans.net/go/acme"
   )

   type MyEventHandler struct{}

   func (h *MyEventHandler) Execute(cmd string) bool {
       fmt.Printf("执行命令: %s\n", cmd)
       return true // 表示已处理该命令
   }

   func (h *MyEventHandler) Look(arg string) bool {
       fmt.Printf("查找: %s\n", arg)
       return true // 表示已处理查找
   }

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       defer win.Del(true)

       go win.EventLoop(&MyEventHandler{})

       // 模拟用户在acme窗口中进行操作
       time.Sleep(2 * time.Second)
   }
   ```
   **假设输入:** 用户在acme窗口中选中一些文本并执行一个命令，或者使用 "Look" 功能。
   **假设输出:**  控制台会输出类似于 `执行命令: ...` 或 `查找: ...` 的信息，具体取决于用户在acme中的操作。

* **`data`**:  用于读取或替换当前地址范围的内容。 (`Write`)
   ```go
   package main

   import (
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       defer win.Del(true)

       win.Addr("0,$") // 选中所有内容
       err = win.Write("data", []byte("新的窗口内容\n"))
       if err != nil {
           log.Println("写入数据失败:", err)
       }
   }
   ```
   **假设输出:**  创建的窗口内容会被替换为 "新的窗口内容"。

* **`xdata`**:  用于读取当前地址范围的完整内容，与 `data` 不同，它总是返回当前选中的内容，无论是否写入。 (`ReadAll`)

* **`errors`**:  用于向窗口的错误区域写入消息。 (`Fprintf`)

**3. 日志功能:**

* **读取acme日志 (`Log`, `LogReader`, `LogEvent`)**:  允许程序读取acme的日志文件，获取窗口创建、删除等事件的信息。
   ```go
   package main

   import (
       "fmt"
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       reader, err := acme.Log()
       if err != nil {
           log.Fatal(err)
       }
       defer reader.Close()

       for {
           event, err := reader.Read()
           if err != nil {
               // 通常是 io.EOF 表示已到达日志末尾
               log.Println("读取日志结束:", err)
               break
           }
           fmt.Printf("日志事件: ID=%d, Op=%s, Name=%s\n", event.ID, event.Op, event.Name)
       }
   }
   ```
   **假设输出:**  会输出acme日志中的事件，例如：
   ```
   日志事件: ID=1, Op=new, Name=/tmp/scratch
   日志事件: ID=1, Op=focus, Name=/tmp/scratch
   日志事件: ID=1, Op=close, Name=/tmp/scratch
   读取日志结束: EOF
   ```

**4. 其他功能:**

* **获取窗口字体信息 (`Font`)**:  返回窗口的tab宽度和字体信息。
* **使窗口标签闪烁 (`Blink`)**:  用于提醒用户注意某个窗口。
* **获取当前选中的文本 (`Selection`)**:  返回窗口中当前选中的内容。
* **设置错误消息的前缀 (`SetErrorPrefix`)**:  用于在错误窗口中区分不同来源的错误信息。
* **显示错误消息 (`Err`)**:  在特定的 "+Errors" 窗口中显示错误信息。
* **排序窗口中的行 (`Sort`)**:  允许根据自定义的比较函数对窗口中选定范围的行进行排序。
* **格式化打印制表符分隔的文本 (`PrintTabbed`)**:  方便地向窗口中打印对齐的表格数据。

**Go 语言功能实现:**

* **与操作系统交互:** 该包通过 `9fans.net/go/plan9/client` 包与Plan 9操作系统的acme服务进行通信，这涉及到Plan 9特有的文件系统概念和通信机制。
* **文件操作抽象:**  将acme窗口的各个方面（控制、内容、地址等）抽象为文件进行操作，这体现了Plan 9 "一切皆文件" 的思想。
* **并发处理:**  使用 `sync.Mutex` 进行互斥锁保护，防止并发访问窗口数据时出现问题。使用 goroutine 和 channel (`EventChan`) 来异步处理acme窗口的事件。
* **字符串处理:**  大量使用 `strings` 包进行字符串的分割、修剪等操作，例如解析 `ctl` 文件的内容或事件消息。
* **类型转换:**  使用 `strconv` 包将字符串转换为数字，例如将窗口ID字符串转换为整数。
* **错误处理:**  函数通常会返回 `error` 类型，用于报告操作失败的原因。

**命令行参数处理:**

该代码本身并没有直接处理命令行参数。它是一个库，供其他Go程序调用来与acme进行交互。调用此库的程序可能会处理命令行参数，但这部分代码未包含在内。

**使用者易犯错的点:**

* **忘记关闭文件描述符:**  `Win` 结构体中包含了多个文件描述符 (`ctl`, `tag`, `body` 等)。如果在使用完 `Win` 对象后不调用 `CloseFiles()` 或者 `Del()`, 可能会导致文件描述符泄漏。
   ```go
   package main

   import (
       "log"

       "9fans.net/go/acme"
   )

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       // 错误示例：忘记关闭文件
       win.Fprintf("body", "一些内容")
       // ... 后续没有调用 win.CloseFiles() 或 win.Del()
   }
   ```
* **在调用 `EventChan()` 后继续调用 `ReadEvent()`:**  `EventChan()` 会启动一个goroutine来读取事件，并将其发送到channel中。如果同时调用 `ReadEvent()`，可能会导致事件被读取两次或者数据竞争。应该只使用 `EventChan()` 返回的channel来接收事件。
   ```go
   package main

   import (
       "fmt"
       "log"
       "time"

       "9fans.net/go/acme"
   )

   func main() {
       win, err := acme.New()
       if err != nil {
           log.Fatal(err)
       }
       defer win.Del(true)

       eventChan := win.EventChan()

       go func() {
           for event := range eventChan {
               fmt.Printf("从Channel接收到事件: %+v\n", event)
           }
       }()

       // 错误示例：同时调用 ReadEvent()
       go func() {
           for {
               event, err := win.ReadEvent()
               if err != nil {
                   log.Println("读取事件出错:", err)
                   return
               }
               fmt.Printf("直接读取到事件: %+v\n", event)
           }
       }()

       time.Sleep(5 * time.Second)
   }
   ```
* **没有正确处理事件循环:**  在使用 `EventLoop` 时，需要理解 `EventHandler` 的 `Execute` 和 `Look` 方法的返回值。如果方法返回 `false`，表示该事件未被处理，`EventLoop` 会将该事件写回acme窗口，让acme的默认行为来处理。如果希望阻止acme的默认行为，应该返回 `true`。

总而言之，这个 `acme` 包提供了一组功能强大的接口，使得Go程序能够方便地与acme编辑器进行交互，实现各种自动化任务和扩展功能。理解acme的内部工作原理和该包提供的抽象是正确使用它的关键。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/vendor/9fans.net/go/acme/acme.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Package acme is a simple interface for interacting with acme windows.
//
// Many of the functions in this package take a format string and optional
// parameters.  In the documentation, the notation format, ... denotes the result
// of formatting the string and arguments using fmt.Sprintf.
package acme // import "9fans.net/go/acme"

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"9fans.net/go/draw"
	"9fans.net/go/plan9"
	"9fans.net/go/plan9/client"
)

// A Win represents a single acme window and its control files.
type Win struct {
	id         int
	ctl        *client.Fid
	tag        *client.Fid
	body       *client.Fid
	addr       *client.Fid
	event      *client.Fid
	data       *client.Fid
	xdata      *client.Fid
	errors     *client.Fid
	ebuf       *bufio.Reader
	c          chan *Event
	next, prev *Win
	buf        []byte
	e2, e3, e4 Event
	name       string

	errorPrefix string
}

var windowsMu sync.Mutex
var windows, last *Win

var fsys *client.Fsys
var fsysErr error
var fsysOnce sync.Once

func mountAcme() {
	fsys, fsysErr = client.MountService("acme")
}

// New creates a new window.
func New() (*Win, error) {
	fsysOnce.Do(mountAcme)
	if fsysErr != nil {
		return nil, fsysErr
	}
	fid, err := fsys.Open("new/ctl", plan9.ORDWR)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 100)
	n, err := fid.Read(buf)
	if err != nil {
		fid.Close()
		return nil, err
	}
	a := strings.Fields(string(buf[0:n]))
	if len(a) == 0 {
		fid.Close()
		return nil, errors.New("short read from acme/new/ctl")
	}
	id, err := strconv.Atoi(a[0])
	if err != nil {
		fid.Close()
		return nil, errors.New("invalid window id in acme/new/ctl: " + a[0])
	}
	return Open(id, fid)
}

type WinInfo struct {
	ID   int
	Name string
}

// A LogReader provides read access to the acme log file.
type LogReader struct {
	f   *client.Fid
	buf [8192]byte
}

func (r *LogReader) Close() error {
	return r.f.Close()
}

// A LogEvent is a single event in the acme log file.
type LogEvent struct {
	ID   int
	Op   string
	Name string
}

// Read reads an event from the acme log file.
func (r *LogReader) Read() (LogEvent, error) {
	n, err := r.f.Read(r.buf[:])
	if err != nil {
		return LogEvent{}, err
	}
	f := strings.SplitN(string(r.buf[:n]), " ", 3)
	if len(f) != 3 {
		return LogEvent{}, fmt.Errorf("malformed log event")
	}
	id, _ := strconv.Atoi(f[0])
	op := f[1]
	name := f[2]
	name = strings.TrimSpace(name)
	return LogEvent{id, op, name}, nil
}

// Log returns a reader reading the acme/log file.
func Log() (*LogReader, error) {
	fsysOnce.Do(mountAcme)
	if fsysErr != nil {
		return nil, fsysErr
	}
	f, err := fsys.Open("log", plan9.OREAD)
	if err != nil {
		return nil, err
	}
	return &LogReader{f: f}, nil
}

// Windows returns a list of the existing acme windows.
func Windows() ([]WinInfo, error) {
	fsysOnce.Do(mountAcme)
	if fsysErr != nil {
		return nil, fsysErr
	}
	index, err := fsys.Open("index", plan9.OREAD)
	if err != nil {
		return nil, err
	}
	defer index.Close()
	data, err := ioutil.ReadAll(index)
	if err != nil {
		return nil, err
	}
	var info []WinInfo
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		n, _ := strconv.Atoi(f[0])
		info = append(info, WinInfo{n, f[5]})
	}
	return info, nil
}

func Show(name string) *Win {
	windowsMu.Lock()
	defer windowsMu.Unlock()

	for w := windows; w != nil; w = w.next {
		if w.name == name {
			if err := w.Ctl("show"); err != nil {
				w.dropLocked()
				return nil
			}
			return w
		}
	}
	return nil
}

// Open connects to the existing window with the given id.
// If ctl is non-nil, Open uses it as the window's control file
// and takes ownership of it.
func Open(id int, ctl *client.Fid) (*Win, error) {
	fsysOnce.Do(mountAcme)
	if fsysErr != nil {
		return nil, fsysErr
	}
	if ctl == nil {
		var err error
		ctl, err = fsys.Open(fmt.Sprintf("%d/ctl", id), plan9.ORDWR)
		if err != nil {
			return nil, err
		}
	}

	w := new(Win)
	w.id = id
	w.ctl = ctl
	w.next = nil
	w.prev = last
	if last != nil {
		last.next = w
	} else {
		windows = w
	}
	last = w
	return w, nil
}

// Addr writes format, ... to the window's addr file.
func (w *Win) Addr(format string, args ...interface{}) error {
	return w.Fprintf("addr", format, args...)
}

// CloseFiles closes all the open files associated with the window w.
// (These file descriptors are cached across calls to Ctl, etc.)
func (w *Win) CloseFiles() {
	w.ctl.Close()
	w.ctl = nil

	w.body.Close()
	w.body = nil

	w.addr.Close()
	w.addr = nil

	w.tag.Close()
	w.tag = nil

	w.event.Close()
	w.event = nil
	w.ebuf = nil

	w.data.Close()
	w.data = nil

	w.xdata.Close()
	w.xdata = nil

	w.errors.Close()
	w.errors = nil
}

// Ctl writes the command format, ... to the window's ctl file.
func (w *Win) Ctl(format string, args ...interface{}) error {
	return w.Fprintf("ctl", format+"\n", args...)
}

// Winctl deletes the window, writing `del' (or, if sure is true, `delete') to the ctl file.
func (w *Win) Del(sure bool) error {
	cmd := "del"
	if sure {
		cmd = "delete"
	}
	return w.Ctl(cmd)
}

// DeleteAll deletes all windows.
func DeleteAll() {
	for w := windows; w != nil; w = w.next {
		w.Ctl("delete")
	}
}

func (w *Win) OpenEvent() error {
	_, err := w.fid("event")
	return err
}

func (w *Win) fid(name string) (*client.Fid, error) {
	var f **client.Fid
	var mode uint8 = plan9.ORDWR
	switch name {
	case "addr":
		f = &w.addr
	case "body":
		f = &w.body
	case "ctl":
		f = &w.ctl
	case "data":
		f = &w.data
	case "event":
		f = &w.event
	case "tag":
		f = &w.tag
	case "xdata":
		f = &w.xdata
	case "errors":
		f = &w.errors
		mode = plan9.OWRITE
	default:
		return nil, errors.New("unknown acme file: " + name)
	}
	if *f == nil {
		var err error
		*f, err = fsys.Open(fmt.Sprintf("%d/%s", w.id, name), mode)
		if err != nil {
			return nil, err
		}
	}
	return *f, nil
}

// ReadAll
func (w *Win) ReadAll(file string) ([]byte, error) {
	f, err := w.fid(file)
	f.Seek(0, 0)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(f)
}

func (w *Win) ID() int {
	return w.id
}

func (w *Win) Name(format string, args ...interface{}) error {
	name := fmt.Sprintf(format, args...)
	if err := w.Ctl("name %s", name); err != nil {
		return err
	}
	w.name = name
	return nil
}

func (w *Win) Fprintf(file, format string, args ...interface{}) error {
	f, err := w.fid(file)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, format, args...)
	_, err = f.Write(buf.Bytes())
	return err
}

func (w *Win) Read(file string, b []byte) (n int, err error) {
	f, err := w.fid(file)
	if err != nil {
		return 0, err
	}
	return f.Read(b)
}

func (w *Win) ReadAddr() (q0, q1 int, err error) {
	f, err := w.fid("addr")
	if err != nil {
		return 0, 0, err
	}
	buf := make([]byte, 40)
	n, err := f.ReadAt(buf, 0)
	if err != nil {
		return 0, 0, err
	}
	a := strings.Fields(string(buf[0:n]))
	if len(a) < 2 {
		return 0, 0, errors.New("short read from acme addr")
	}
	q0, err0 := strconv.Atoi(a[0])
	q1, err1 := strconv.Atoi(a[1])
	if err0 != nil || err1 != nil {
		return 0, 0, errors.New("invalid read from acme addr")
	}
	return q0, q1, nil
}

func (w *Win) Seek(file string, offset int64, whence int) (int64, error) {
	f, err := w.fid(file)
	if err != nil {
		return 0, err
	}
	return f.Seek(offset, whence)
}

func (w *Win) Write(file string, b []byte) (n int, err error) {
	f, err := w.fid(file)
	if err != nil {
		return 0, err
	}
	return f.Write(b)
}

const eventSize = 256

// An Event represents an event originating in a particular window.
// The fields correspond to the fields in acme's event messages.
// See http://swtch.com/plan9port/man/man4/acme.html for details.
type Event struct {
	// The two event characters, indicating origin and type of action
	C1, C2 rune

	// The character addresses of the action.
	// If the original event had an empty selection (OrigQ0=OrigQ1)
	// and was accompanied by an expansion (the 2 bit is set in Flag),
	// then Q0 and Q1 will indicate the expansion rather than the
	// original event.
	Q0, Q1 int

	// The Q0 and Q1 of the original event, even if it was expanded.
	// If there was no expansion, OrigQ0=Q0 and OrigQ1=Q1.
	OrigQ0, OrigQ1 int

	// The flag bits.
	Flag int

	// The number of bytes in the optional text.
	Nb int

	// The number of characters (UTF-8 sequences) in the optional text.
	Nr int

	// The optional text itself, encoded in UTF-8.
	Text []byte

	// The chorded argument, if present (the 8 bit is set in the flag).
	Arg []byte

	// The chorded location, if present (the 8 bit is set in the flag).
	Loc []byte
}

// ReadEvent reads the next event from the window's event file.
func (w *Win) ReadEvent() (e *Event, err error) {
	defer func() {
		if v := recover(); v != nil {
			e = nil
			err = errors.New("malformed acme event: " + v.(string))
		}
	}()

	if _, err = w.fid("event"); err != nil {
		return nil, err
	}

	e = new(Event)
	w.gete(e)
	e.OrigQ0 = e.Q0
	e.OrigQ1 = e.Q1

	// expansion
	if e.Flag&2 != 0 {
		e2 := new(Event)
		w.gete(e2)
		if e.Q0 == e.Q1 {
			e2.OrigQ0 = e.Q0
			e2.OrigQ1 = e.Q1
			e2.Flag = e.Flag
			e = e2
		}
	}

	// chorded argument
	if e.Flag&8 != 0 {
		e3 := new(Event)
		e4 := new(Event)
		w.gete(e3)
		w.gete(e4)
		e.Arg = e3.Text
		e.Loc = e4.Text
	}

	return e, nil
}

func (w *Win) gete(e *Event) {
	if w.ebuf == nil {
		w.ebuf = bufio.NewReader(w.event)
	}
	e.C1 = w.getec()
	e.C2 = w.getec()
	e.Q0 = w.geten()
	e.Q1 = w.geten()
	e.Flag = w.geten()
	e.Nr = w.geten()
	if e.Nr > eventSize {
		panic("event string too long")
	}
	r := make([]rune, e.Nr)
	for i := 0; i < e.Nr; i++ {
		r[i] = w.getec()
	}
	e.Text = []byte(string(r))
	if w.getec() != '\n' {
		panic("phase error")
	}
}

func (w *Win) getec() rune {
	c, _, err := w.ebuf.ReadRune()
	if err != nil {
		panic(err.Error())
	}
	return c
}

func (w *Win) geten() int {
	var (
		c rune
		n int
	)
	for {
		c = w.getec()
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c) - '0'
	}
	if c != ' ' {
		panic("event number syntax")
	}
	return n
}

// WriteEvent writes an event back to the window's event file,
// indicating to acme that the event should be handled internally.
func (w *Win) WriteEvent(e *Event) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%c%c%d %d \n", e.C1, e.C2, e.Q0, e.Q1)
	_, err := w.Write("event", buf.Bytes())
	return err
}

// EventChan returns a channel on which events can be read.
// The first call to EventChan allocates a channel and starts a
// new goroutine that loops calling ReadEvent and sending
// the result into the channel.  Subsequent calls return the
// same channel.  Clients should not call ReadEvent after calling
// EventChan.
func (w *Win) EventChan() <-chan *Event {
	if w.c == nil {
		w.c = make(chan *Event, 0)
		go w.eventReader()
	}
	return w.c
}

func (w *Win) eventReader() {
	for {
		e, err := w.ReadEvent()
		if err != nil {
			break
		}
		w.c <- e
	}
	w.drop()
	close(w.c)
}

func (w *Win) drop() {
	windowsMu.Lock()
	defer windowsMu.Unlock()
	w.dropLocked()
}

func (w *Win) dropLocked() {
	if w.prev == nil && w.next == nil && windows != w {
		return
	}
	if w.prev != nil {
		w.prev.next = w.next
	} else {
		windows = w.next
	}
	if w.next != nil {
		w.next.prev = w.prev
	} else {
		last = w.prev
	}
	w.prev = nil
	w.next = nil
}

var fontCache struct {
	sync.Mutex
	m map[string]*draw.Font
}

// Font returns the window's current tab width (in zeros) and font.
func (w *Win) Font() (tab int, font *draw.Font, err error) {
	ctl := make([]byte, 1000)
	w.Seek("ctl", 0, 0)
	n, err := w.Read("ctl", ctl)
	if err != nil {
		return 0, nil, err
	}
	f := strings.Fields(string(ctl[:n]))
	if len(f) < 8 {
		return 0, nil, fmt.Errorf("malformed ctl file")
	}
	tab, _ = strconv.Atoi(f[7])
	if tab == 0 {
		return 0, nil, fmt.Errorf("malformed ctl file")
	}
	name := f[6]

	fontCache.Lock()
	font = fontCache.m[name]
	fontCache.Unlock()

	if font != nil {
		return tab, font, nil
	}

	var disp *draw.Display = nil
	font, err = disp.OpenFont(name)
	if err != nil {
		return tab, nil, err
	}

	fontCache.Lock()
	if fontCache.m == nil {
		fontCache.m = make(map[string]*draw.Font)
	}
	if fontCache.m[name] != nil {
		font = fontCache.m[name]
	} else {
		fontCache.m[name] = font
	}
	fontCache.Unlock()

	return tab, font, nil
}

// Blink starts the window tag blinking and returns a function that stops it.
// When stop returns, the blinking is over.
func (w *Win) Blink() (stop func()) {
	c := make(chan struct{})
	go func() {
		t := time.NewTicker(1000 * time.Millisecond)
		defer t.Stop()
		dirty := false
		for {
			select {
			case <-t.C:
				dirty = !dirty
				if dirty {
					w.Ctl("dirty")
				} else {
					w.Ctl("clean")
				}
			case <-c:
				if dirty {
					w.Ctl("clean")
				}
				c <- struct{}{}
				return
			}
		}
	}()
	return func() {
		c <- struct{}{}
		<-c
	}
}

// Sort sorts the lines in the current address range
// according to the comparison function.
func (w *Win) Sort(less func(x, y string) bool) error {
	q0, q1, err := w.ReadAddr()
	if err != nil {
		return err
	}
	data, err := w.ReadAll("xdata")
	if err != nil {
		return err
	}
	suffix := ""
	lines := strings.Split(string(data), "\n")
	if lines[len(lines)-1] == "" {
		suffix = "\n"
		lines = lines[:len(lines)-1]
	}
	sort.SliceStable(lines, func(i, j int) bool { return less(lines[i], lines[j]) })
	w.Addr("#%d,#%d", q0, q1)
	w.Write("data", []byte(strings.Join(lines, "\n")+suffix))
	return nil
}

// PrintTabbed prints tab-separated columnated text to body,
// replacing single tabs with runs of tabs as needed to align columns.
func (w *Win) PrintTabbed(text string) {
	tab, font, _ := w.Font()

	lines := strings.SplitAfter(text, "\n")
	var allRows [][]string
	for _, line := range lines {
		if line == "" {
			continue
		}
		line = strings.TrimSuffix(line, "\n")
		allRows = append(allRows, strings.Split(line, "\t"))
	}

	var buf bytes.Buffer
	for len(allRows) > 0 {
		if row := allRows[0]; len(row) <= 1 {
			if len(row) > 0 {
				buf.WriteString(row[0])
			}
			buf.WriteString("\n")
			allRows = allRows[1:]
			continue
		}

		i := 0
		for i < len(allRows) && len(allRows[i]) > 1 {
			i++
		}

		rows := allRows[:i]
		allRows = allRows[i:]

		var wid []int
		if font != nil {
			for _, row := range rows {
				for len(wid) < len(row) {
					wid = append(wid, 0)
				}
				for i, col := range row {
					n := font.StringWidth(col)
					if wid[i] < n {
						wid[i] = n
					}
				}
			}
		}

		for _, row := range rows {
			for i, col := range row {
				buf.WriteString(col)
				if i == len(row)-1 {
					break
				}
				if font == nil || tab == 0 {
					buf.WriteString("\t")
					continue
				}
				pos := font.StringWidth(col)
				for pos <= wid[i] {
					buf.WriteString("\t")
					pos += tab - pos%tab
				}
			}
			buf.WriteString("\n")
		}
	}

	w.Write("body", buf.Bytes())
}

// Clear clears the window body.
func (w *Win) Clear() {
	w.Addr(",")
	w.Write("data", nil)
}

type EventHandler interface {
	Execute(cmd string) bool
	Look(arg string) bool
}

func (w *Win) loadText(e *Event, h EventHandler) {
	if len(e.Text) == 0 && e.Q0 < e.Q1 {
		w.Addr("#%d,#%d", e.Q0, e.Q1)
		data, err := w.ReadAll("xdata")
		if err != nil {
			w.Err(err.Error())
		}
		e.Text = data
	}
}

func (w *Win) EventLoop(h EventHandler) {
	for e := range w.EventChan() {
		switch e.C2 {
		case 'x', 'X': // execute
			cmd := strings.TrimSpace(string(e.Text))
			if !h.Execute(cmd) {
				w.WriteEvent(e)
			}
		case 'l', 'L': // look
			// TODO(rsc): Expand selection, especially for URLs.
			w.loadText(e, h)
			if !h.Look(string(e.Text)) {
				w.WriteEvent(e)
			}
		}
	}
}

func (w *Win) Selection() string {
	w.Ctl("addr=dot")
	data, err := w.ReadAll("xdata")
	if err != nil {
		w.Err(err.Error())
	}
	return string(data)
}

func (w *Win) SetErrorPrefix(p string) {
	w.errorPrefix = p
}

func (w *Win) Err(s string) {
	if !strings.HasSuffix(s, "\n") {
		s = s + "\n"
	}
	w1 := Show(w.errorPrefix + "+Errors")
	if w1 == nil {
		var err error
		w1, err = New()
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			w1, err = New()
			if err != nil {
				log.Fatalf("cannot create +Errors window")
			}
		}
		w1.Name("%s", w.errorPrefix+"+Errors")
	}
	w1.Fprintf("body", "%s", s)
	w1.Addr("$")
	w1.Ctl("dot=addr")
	w1.Ctl("show")
}

"""



```