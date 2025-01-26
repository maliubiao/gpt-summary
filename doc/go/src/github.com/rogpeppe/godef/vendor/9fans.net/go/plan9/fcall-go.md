Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Context:**

The first and most crucial step is recognizing the file path: `go/src/github.com/rogpeppe/godef/vendor/9fans.net/go/plan9/fcall.go`. This immediately tells us several things:

* **Plan 9:** This code is related to the Plan 9 operating system. This gives us a strong hint about the underlying concepts and protocols likely involved. Plan 9 is known for its "everything is a file" philosophy and its own network protocol, 9P.
* **`fcall.go`:** The filename suggests this file handles function calls or remote procedure calls, specifically related to the Plan 9 context.
* **`vendor` directory:**  This indicates the code is a dependency. `godef` likely uses this library for interacting with Plan 9 systems or services.

**2. Initial Code Scan - Identifying Key Structures and Constants:**

A quick skim of the code reveals:

* **`Fcall` struct:** This is the central data structure. Its fields like `Type`, `Fid`, `Tag`, `Msize`, `Version`, `Data`, `Stat`, etc., strongly suggest it represents a message or request/response in a communication protocol. The varying fields depending on `Type` is a key observation.
* **Constants (Tversion, Rversion, Tauth, etc.):** These constants clearly enumerate different types of messages or operations. The `T` prefix likely means "Transmit" (request), and `R` likely means "Receive" (response).
* **`IOHDRSIZE`:**  A constant likely related to header size.
* **`Bytes()` and `UnmarshalFcall()` methods:** These are crucial for serialization and deserialization of the `Fcall` struct. This confirms the idea of a network protocol.
* **`String()` method:**  Used for debugging and logging, providing a human-readable representation of `Fcall` instances.
* **`ReadFcall()` and `WriteFcall()` functions:**  These functions handle reading and writing `Fcall` structures from/to an `io.Reader` and `io.Writer`, further solidifying the network communication aspect.
* **Helper functions (pbit*, gbit*, pstring, gstring, pqid, gqid, pperm, gperm):** These are lower-level functions for packing and unpacking data into byte streams, hinting at a custom binary protocol.

**3. Connecting the Dots - Inferring the Protocol (9P):**

Based on the "Plan 9" context and the structure of `Fcall`, it becomes highly likely this code implements a significant portion of the Plan 9 File Protocol (9P). The types of messages (Tversion, Tauth, Tattach, Topen, Tread, Twrite, etc.) correspond to typical file system operations, which are fundamental to 9P.

**4. Functionality Listing:**

Now, we can systematically list the functionalities based on the code:

* **Represents 9P messages:** The `Fcall` struct is the core representation.
* **Serialization (`Bytes()`):** Converts `Fcall` to a byte stream for transmission.
* **Deserialization (`UnmarshalFcall()`):** Converts a byte stream back into an `Fcall`.
* **Specific message types:** Supports various 9P message types (Tversion, Rversion, etc.).
* **String representation (`String()`):** Provides a human-readable format for debugging.
* **Reading `Fcall` from a stream (`ReadFcall()`):**  Handles reading from an `io.Reader`.
* **Writing `Fcall` to a stream (`WriteFcall()`):** Handles writing to an `io.Writer`.
* **Data packing and unpacking:** Utilizes helper functions for managing the binary format.

**5. Code Example and Reasoning:**

To illustrate how this is used, we need a scenario involving client-server communication using 9P. The most basic example is establishing a connection and exchanging version information:

* **Client:** Sends a `Tversion` message.
* **Server:** Responds with an `Rversion` message.

This leads to the Go code example demonstrating the creation and marshaling/unmarshaling of these message types. The assumed inputs and outputs are based on the structure of the `Tversion` and `Rversion` messages.

**6. Identifying Potential Errors:**

By examining the `Bytes()` and `UnmarshalFcall()` methods, we can identify potential error conditions:

* **Invalid message type:**  The `default` case in the `switch` statements.
* **Too many elements in a walk:** The checks for `len(f.Wname) > MAXWELEM` and `len(f.Wqid) > MAXWELEM`.
* **Malformed data during unmarshaling:**  The `panic(1)` calls indicate potential issues if the byte stream doesn't match the expected format. The `recover()` mechanism is in place to catch these panics and return a `ProtocolError`.

**7. Command-Line Arguments (Not Applicable):**

This code snippet is a library, not a standalone executable. Therefore, it doesn't directly handle command-line arguments. `godef`, the project this code belongs to, *does* have command-line arguments, but this specific file is focused on the 9P protocol logic.

**8. Common Mistakes (Based on the Code):**

Thinking about how developers might use this, potential pitfalls arise:

* **Incorrectly constructing `Fcall` structs:**  Forgetting to set required fields or setting them to incorrect values.
* **Mismatched message types:** Sending a request expecting a different type of response.
* **Not handling `ProtocolError`:** Ignoring the possibility of errors during serialization/deserialization.
* **Incorrectly sizing data buffers:** Errors could occur if buffer sizes are not correctly managed when dealing with the `Data` and `Stat` fields.

By following this detailed thought process, combining code analysis with domain knowledge (Plan 9 and 9P), and considering potential usage scenarios, we can arrive at a comprehensive understanding of the provided Go code snippet.
这段代码是 Go 语言中用于处理 Plan 9 操作系统中消息协议（通常称为 9P 协议）的实现的一部分。它定义了消息的结构体 `Fcall` 以及序列化和反序列化这些消息的方法。

**功能列举:**

1. **定义 9P 协议消息结构体 `Fcall`:**  `Fcall` 结构体包含了 9P 协议中各种消息类型共有的和特定的字段，例如消息类型 (`Type`)、文件标识符 (`Fid`)、标签 (`Tag`)、数据大小 (`Msize`)、版本号 (`Version`)、文件名 (`Name`)、偏移量 (`Offset`)、数据 (`Data`) 等。
2. **定义 9P 协议消息类型常量:**  定义了 `Tversion`, `Rversion`, `Tauth`, `Rauth` 等常量，分别代表客户端请求和服务器响应的各种消息类型。
3. **序列化 `Fcall` 结构体为字节数组 (`Bytes()`):**  `Bytes()` 方法将 `Fcall` 结构体转换为可以进行网络传输的字节数组。它根据 `Fcall` 的 `Type` 字段，将不同的字段按照 9P 协议的格式打包到字节数组中。
4. **反序列化字节数组为 `Fcall` 结构体 (`UnmarshalFcall()`):** `UnmarshalFcall()` 函数接收一个字节数组，并根据 9P 协议的格式将其解析为一个 `Fcall` 结构体。它根据字节数组中的消息类型，提取出相应的字段值。
5. **提供 `Fcall` 结构体的字符串表示 (`String()`):**  `String()` 方法返回 `Fcall` 结构体的易于阅读的字符串表示，方便调试和日志记录。
6. **从 `io.Reader` 读取并反序列化 `Fcall` (`ReadFcall()`):**  `ReadFcall()` 函数从一个 `io.Reader` 中读取 9P 消息的字节流，并使用 `UnmarshalFcall()` 将其反序列化为 `Fcall` 结构体。它首先读取消息的长度，然后读取剩余的数据。
7. **将 `Fcall` 结构体序列化并写入 `io.Writer` (`WriteFcall()`):**  `WriteFcall()` 函数将 `Fcall` 结构体使用 `Bytes()` 方法序列化为字节数组，并将该字节数组写入到提供的 `io.Writer` 中。

**推理：实现 9P 协议的编解码**

这段代码核心实现了 9P 协议中消息的编码（序列化）和解码（反序列化）功能。9P 协议是 Plan 9 操作系统及其衍生系统（如 Inferno）中用于进程间通信和客户端-服务器通信的主要协议。它允许程序以统一的方式访问各种资源，例如文件系统、网络连接等。

**Go 代码示例:**

假设我们有一个客户端想要向服务器发送一个版本协商请求 (Tversion) 并接收服务器的响应 (Rversion)。

```go
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/rogpeppe/godef/vendor/9fans.net/go/plan9"
)

func main() {
	// 模拟客户端发送 Tversion 消息
	tversion := plan9.Fcall{
		Type:    plan9.Tversion,
		Tag:     1, // 通常客户端会使用一个唯一的 tag
		Msize:   8192,
		Version: "9P2000",
	}

	// 序列化 Tversion 消息
	tversionBytes, err := tversion.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("发送的 Tversion 消息字节: %v\n", tversionBytes)

	// 模拟接收服务器的 Rversion 消息 (假设从网络连接中读取)
	// 这里为了演示，直接创建一个 Rversion 消息的字节数组
	rversionBytes := []byte{
		0, 0, 0, 18, // 消息总长度
		101,       // Rversion 类型
		0, 1,       // Tag (与请求的 Tag 对应)
		0, 0, 20, 0, // Msize
		6, 0, '9', 'P', '2', '0', '0', // Version
	}

	// 反序列化 Rversion 消息
	rversion := &plan9.Fcall{}
	err = rversion.Unmarshal(rversionBytes) // 注意: 原始代码没有 Unmarshal 方法，这里假设存在或使用 UnmarshalFcall
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("接收到的 Rversion 消息: %s\n", rversion.String())
}

// 为了演示，添加一个 Unmarshal 方法到 Fcall 结构体 (与原始代码的 UnmarshalFcall 功能相同)
func (f *plan9.Fcall) Unmarshal(b []byte) error {
	var err error
	f, err = plan9.UnmarshalFcall(b)
	return err
}
```

**假设的输入与输出:**

* **输入 (模拟的 Tversion 消息数据):**  根据 `tversion` 结构体的字段，`tversion.Bytes()` 方法会生成一个包含消息长度、消息类型、Tag、Msize 和 Version 的字节数组。
* **输出 (模拟的 Rversion 消息数据):**  `UnmarshalFcall()` 函数接收 `rversionBytes` 字节数组，并将其解析为一个 `plan9.Fcall` 结构体。`rversion.String()` 方法会输出类似 "Rversion tag 1 msize 8192 version '9P2000'" 的字符串。

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。它是一个库，用于处理 9P 协议的消息。具体的命令行参数处理通常会在使用这个库的应用程序中进行。例如，如果有一个使用此库的 9P 客户端程序，它可能会有命令行参数来指定连接的服务器地址、端口等。

**使用者易犯错的点:**

1. **不正确的消息类型:**  在构造 `Fcall` 结构体时，如果 `Type` 字段设置错误，会导致序列化或反序列化失败，或者服务器无法正确处理请求。 例如，客户端本应发送 `Topen` 请求，却错误地设置了 `Type` 为 `Tcreate`。

   ```go
   // 错误示例：应该发送 Topen，却发送了 Tcreate
   badFcall := plan9.Fcall{
       Type: plan9.Tcreate, // 错误的类型
       Fid:  1,
       Mode: 0,
   }
   ```

2. **遗漏或错误设置必要字段:**  不同的消息类型有不同的必要字段。如果构造 `Fcall` 结构体时遗漏了必要的字段，或者设置了错误的值，会导致序列化后的数据不符合 9P 协议规范，从而导致通信失败。 例如，发送 `Twrite` 请求时，没有设置 `Data` 字段。

   ```go
   // 错误示例：发送 Twrite 没有设置 Data
   badWrite := plan9.Fcall{
       Type:   plan9.Twrite,
       Fid:    1,
       Offset: 0,
       Count:  10,
       // 缺少 Data 字段
   }
   ```

3. **处理字节数组时的长度错误:**  在手动构建或解析字节数组时，容易出现长度计算错误，导致 `Bytes()` 或 `UnmarshalFcall()` 函数出错。 例如，手动构造 Rversion 的字节数组时，消息总长度计算错误。

4. **Tag 的管理不当:**  9P 协议使用 Tag 来匹配请求和响应。客户端需要正确地生成和管理 Tag，以确保能够将服务器的响应与对应的请求关联起来。如果 Tag 的使用出现混乱，会导致响应无法正确处理。

总之，这段代码是实现 9P 协议的关键部分，它负责将 Go 语言的数据结构转换为网络传输的字节流，以及将接收到的字节流转换回 Go 语言的数据结构。理解 9P 协议的规范和每个消息类型的字段是正确使用这段代码的关键。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/vendor/9fans.net/go/plan9/fcall.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package plan9

import (
	"fmt"
	"io"
)

const (
	IOHDRSIZE = 24
)

type Fcall struct {
	Type    uint8
	Fid     uint32
	Tag     uint16
	Msize   uint32
	Version string   // Tversion, Rversion
	Oldtag  uint16   // Tflush
	Ename   string   // Rerror
	Qid     Qid      // Rattach, Ropen, Rcreate
	Iounit  uint32   // Ropen, Rcreate
	Aqid    Qid      // Rauth
	Afid    uint32   // Tauth, Tattach
	Uname   string   // Tauth, Tattach
	Aname   string   // Tauth, Tattach
	Perm    Perm     // Tcreate
	Name    string   // Tcreate
	Mode    uint8    // Tcreate, Topen
	Newfid  uint32   // Twalk
	Wname   []string // Twalk
	Wqid    []Qid    // Rwalk
	Offset  uint64   // Tread, Twrite
	Count   uint32   // Tread, Rwrite
	Data    []byte   // Twrite, Rread
	Stat    []byte   // Twstat, Rstat

	// 9P2000.u extensions
	Errno     uint32 // Rerror
	Uid       uint32 // Tattach, Tauth
	Extension string // Tcreate
}

const (
	Tversion = 100 + iota
	Rversion
	Tauth
	Rauth
	Tattach
	Rattach
	Terror // illegal
	Rerror
	Tflush
	Rflush
	Twalk
	Rwalk
	Topen
	Ropen
	Tcreate
	Rcreate
	Tread
	Rread
	Twrite
	Rwrite
	Tclunk
	Rclunk
	Tremove
	Rremove
	Tstat
	Rstat
	Twstat
	Rwstat
	Tmax
)

func (f *Fcall) Bytes() ([]byte, error) {
	b := pbit32(nil, 0) // length: fill in later
	b = pbit8(b, f.Type)
	b = pbit16(b, f.Tag)
	switch f.Type {
	default:
		return nil, ProtocolError("invalid type")

	case Tversion:
		b = pbit32(b, f.Msize)
		b = pstring(b, f.Version)

	case Tflush:
		b = pbit16(b, f.Oldtag)

	case Tauth:
		b = pbit32(b, f.Afid)
		b = pstring(b, f.Uname)
		b = pstring(b, f.Aname)

	case Tattach:
		b = pbit32(b, f.Fid)
		b = pbit32(b, f.Afid)
		b = pstring(b, f.Uname)
		b = pstring(b, f.Aname)

	case Twalk:
		b = pbit32(b, f.Fid)
		b = pbit32(b, f.Newfid)
		if len(f.Wname) > MAXWELEM {
			return nil, ProtocolError("too many names in walk")
		}
		b = pbit16(b, uint16(len(f.Wname)))
		for i := range f.Wname {
			b = pstring(b, f.Wname[i])
		}

	case Topen:
		b = pbit32(b, f.Fid)
		b = pbit8(b, f.Mode)

	case Tcreate:
		b = pbit32(b, f.Fid)
		b = pstring(b, f.Name)
		b = pperm(b, f.Perm)
		b = pbit8(b, f.Mode)

	case Tread:
		b = pbit32(b, f.Fid)
		b = pbit64(b, f.Offset)
		b = pbit32(b, f.Count)

	case Twrite:
		b = pbit32(b, f.Fid)
		b = pbit64(b, f.Offset)
		b = pbit32(b, uint32(len(f.Data)))
		b = append(b, f.Data...)

	case Tclunk, Tremove, Tstat:
		b = pbit32(b, f.Fid)

	case Twstat:
		b = pbit32(b, f.Fid)
		b = pbit16(b, uint16(len(f.Stat)))
		b = append(b, f.Stat...)

	case Rversion:
		b = pbit32(b, f.Msize)
		b = pstring(b, f.Version)

	case Rerror:
		b = pstring(b, f.Ename)

	case Rflush, Rclunk, Rremove, Rwstat:
		// nothing

	case Rauth:
		b = pqid(b, f.Aqid)

	case Rattach:
		b = pqid(b, f.Qid)

	case Rwalk:
		if len(f.Wqid) > MAXWELEM {
			return nil, ProtocolError("too many qid in walk")
		}
		b = pbit16(b, uint16(len(f.Wqid)))
		for i := range f.Wqid {
			b = pqid(b, f.Wqid[i])
		}

	case Ropen, Rcreate:
		b = pqid(b, f.Qid)
		b = pbit32(b, f.Iounit)

	case Rread:
		b = pbit32(b, uint32(len(f.Data)))
		b = append(b, f.Data...)

	case Rwrite:
		b = pbit32(b, f.Count)

	case Rstat:
		b = pbit16(b, uint16(len(f.Stat)))
		b = append(b, f.Stat...)
	}

	pbit32(b[0:0], uint32(len(b)))
	return b, nil
}

func UnmarshalFcall(b []byte) (f *Fcall, err error) {
	defer func() {
		if recover() != nil {
			println("bad fcall at ", b)
			f = nil
			err = ProtocolError("malformed Fcall")
		}
	}()

	n, b := gbit32(b)
	if len(b) != int(n)-4 {
		panic(1)
	}

	f = new(Fcall)
	f.Type, b = gbit8(b)
	f.Tag, b = gbit16(b)

	switch f.Type {
	default:
		panic(1)

	case Tversion:
		f.Msize, b = gbit32(b)
		f.Version, b = gstring(b)

	case Tflush:
		f.Oldtag, b = gbit16(b)

	case Tauth:
		f.Afid, b = gbit32(b)
		f.Uname, b = gstring(b)
		f.Aname, b = gstring(b)

	case Tattach:
		f.Fid, b = gbit32(b)
		f.Afid, b = gbit32(b)
		f.Uname, b = gstring(b)
		f.Aname, b = gstring(b)

	case Twalk:
		f.Fid, b = gbit32(b)
		f.Newfid, b = gbit32(b)
		var n uint16
		n, b = gbit16(b)
		if n > MAXWELEM {
			panic(1)
		}
		f.Wname = make([]string, n)
		for i := range f.Wname {
			f.Wname[i], b = gstring(b)
		}

	case Topen:
		f.Fid, b = gbit32(b)
		f.Mode, b = gbit8(b)

	case Tcreate:
		f.Fid, b = gbit32(b)
		f.Name, b = gstring(b)
		f.Perm, b = gperm(b)
		f.Mode, b = gbit8(b)

	case Tread:
		f.Fid, b = gbit32(b)
		f.Offset, b = gbit64(b)
		f.Count, b = gbit32(b)

	case Twrite:
		f.Fid, b = gbit32(b)
		f.Offset, b = gbit64(b)
		n, b = gbit32(b)
		if len(b) != int(n) {
			panic(1)
		}
		f.Data = b
		b = nil

	case Tclunk, Tremove, Tstat:
		f.Fid, b = gbit32(b)

	case Twstat:
		f.Fid, b = gbit32(b)
		var n uint16
		n, b = gbit16(b)
		if len(b) != int(n) {
			panic(1)
		}
		f.Stat = b
		b = nil

	case Rversion:
		f.Msize, b = gbit32(b)
		f.Version, b = gstring(b)

	case Rerror:
		f.Ename, b = gstring(b)

	case Rflush, Rclunk, Rremove, Rwstat:
		// nothing

	case Rauth:
		f.Aqid, b = gqid(b)

	case Rattach:
		f.Qid, b = gqid(b)

	case Rwalk:
		var n uint16
		n, b = gbit16(b)
		if n > MAXWELEM {
			panic(1)
		}
		f.Wqid = make([]Qid, n)
		for i := range f.Wqid {
			f.Wqid[i], b = gqid(b)
		}

	case Ropen, Rcreate:
		f.Qid, b = gqid(b)
		f.Iounit, b = gbit32(b)

	case Rread:
		n, b = gbit32(b)
		if len(b) != int(n) {
			panic(1)
		}
		f.Data = b
		b = nil

	case Rwrite:
		f.Count, b = gbit32(b)

	case Rstat:
		var n uint16
		n, b = gbit16(b)
		if len(b) != int(n) {
			panic(1)
		}
		f.Stat = b
		b = nil
	}

	if len(b) != 0 {
		panic(1)
	}

	return f, nil
}

func (f *Fcall) String() string {
	if f == nil {
		return "<nil>"
	}
	switch f.Type {
	case Tversion:
		return fmt.Sprintf("Tversion tag %d msize %d version '%s'",
			f.Tag, f.Msize, f.Version)
	case Rversion:
		return fmt.Sprintf("Rversion tag %d msize %d version '%s'",
			f.Tag, f.Msize, f.Version)
	case Tauth:
		return fmt.Sprintf("Tauth tag %d afid %d uname %s aname %s",
			f.Tag, f.Afid, f.Uname, f.Aname)
	case Rauth:
		return fmt.Sprintf("Rauth tag %d qid %v", f.Tag, f.Qid)
	case Tattach:
		return fmt.Sprintf("Tattach tag %d fid %d afid %d uname %s aname %s",
			f.Tag, f.Fid, f.Afid, f.Uname, f.Aname)
	case Rattach:
		return fmt.Sprintf("Rattach tag %d qid %v", f.Tag, f.Qid)
	case Rerror:
		return fmt.Sprintf("Rerror tag %d ename %s", f.Tag, f.Ename)
	case Tflush:
		return fmt.Sprintf("Tflush tag %d oldtag %d", f.Tag, f.Oldtag)
	case Rflush:
		return fmt.Sprintf("Rflush tag %d", f.Tag)
	case Twalk:
		return fmt.Sprintf("Twalk tag %d fid %d newfid %d wname %v",
			f.Tag, f.Fid, f.Newfid, f.Wname)
	case Rwalk:
		return fmt.Sprintf("Rwalk tag %d wqid %v", f.Tag, f.Wqid)
	case Topen:
		return fmt.Sprintf("Topen tag %d fid %d mode %d", f.Tag, f.Fid, f.Mode)
	case Ropen:
		return fmt.Sprintf("Ropen tag %d qid %v iouint %d", f.Tag, f.Qid, f.Iounit)
	case Tcreate:
		return fmt.Sprintf("Tcreate tag %d fid %d name %s perm %v mode %d",
			f.Tag, f.Fid, f.Name, f.Perm, f.Mode)
	case Rcreate:
		return fmt.Sprintf("Rcreate tag %d qid %v iouint %d", f.Tag, f.Qid, f.Iounit)
	case Tread:
		return fmt.Sprintf("Tread tag %d fid %d offset %d count %d",
			f.Tag, f.Fid, f.Offset, f.Count)
	case Rread:
		return fmt.Sprintf("Rread tag %d count %d %s",
			f.Tag, len(f.Data), dumpsome(f.Data))
	case Twrite:
		return fmt.Sprintf("Twrite tag %d fid %d offset %d count %d %s",
			f.Tag, f.Fid, f.Offset, len(f.Data), dumpsome(f.Data))
	case Rwrite:
		return fmt.Sprintf("Rwrite tag %d count %d", f.Tag, f.Count)
	case Tclunk:
		return fmt.Sprintf("Tclunk tag %d fid %d", f.Tag, f.Fid)
	case Rclunk:
		return fmt.Sprintf("Rclunk tag %d", f.Tag)
	case Tremove:
		return fmt.Sprintf("Tremove tag %d fid %d", f.Tag, f.Fid)
	case Rremove:
		return fmt.Sprintf("Rremove tag %d", f.Tag)
	case Tstat:
		return fmt.Sprintf("Tstat tag %d fid %d", f.Tag, f.Fid)
	case Rstat:
		d, err := UnmarshalDir(f.Stat)
		if err == nil {
			return fmt.Sprintf("Rstat tag %d stat(%d bytes)",
				f.Tag, len(f.Stat))
		}
		return fmt.Sprintf("Rstat tag %d stat %v", f.Tag, d)
	case Twstat:
		d, err := UnmarshalDir(f.Stat)
		if err == nil {
			return fmt.Sprintf("Twstat tag %d fid %d stat(%d bytes)",
				f.Tag, f.Fid, len(f.Stat))
		}
		return fmt.Sprintf("Twstat tag %d fid %d stat %v", f.Tag, f.Fid, d)
	case Rwstat:
		return fmt.Sprintf("FidRwstat tag %d", f.Tag)
	}
	return fmt.Sprintf("unknown type %d", f.Type)
}

func ReadFcall(r io.Reader) (*Fcall, error) {
	// 128 bytes should be enough for most messages
	buf := make([]byte, 128)
	_, err := io.ReadFull(r, buf[0:4])
	if err != nil {
		return nil, err
	}

	// read 4-byte header, make room for remainder
	n, _ := gbit32(buf)
	if n < 4 {
		return nil, ProtocolError("invalid length")
	}
	if int(n) <= len(buf) {
		buf = buf[0:n]
	} else {
		buf = make([]byte, n)
		pbit32(buf[0:0], n)
	}

	// read remainder and unpack
	_, err = io.ReadFull(r, buf[4:])
	if err != nil {
		return nil, err
	}
	return UnmarshalFcall(buf)
}

func WriteFcall(w io.Writer, f *Fcall) error {
	b, err := f.Bytes()
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

"""



```