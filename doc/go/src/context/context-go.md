Response:
我的目标是分析给定的Go语言 `context` 包的源代码，并根据用户的要求进行回答。

**1. 理解用户需求：**

用户要求我列举 `context.go` 的功能，并尽可能推断出其实现的功能。对于推断出的功能，需要提供Go代码示例，包括假设的输入和输出。此外，还需要说明命令行参数的处理（尽管 `context` 包本身不直接处理命令行参数，需要考虑如何解释），以及列举使用者容易犯错的点。最后，所有的回答需要用中文。

**2. 功能分析：**

仔细阅读代码和注释，可以提取出以下核心功能：

* **Context 类型定义:** 定义了 `Context` 接口，它包含了 `Deadline()`, `Done()`, `Err()`, 和 `Value()` 方法。这是包的核心抽象。
* **上下文创建函数:**
    * `Background()`: 创建一个顶级的、永远不会取消的上下文。
    * `TODO()`:  创建一个在不确定使用哪个上下文时的占位符。
    * `WithCancel()`: 创建一个可取消的子上下文，返回新的上下文和一个取消函数。
    * `WithCancelCause()`: 创建一个可取消的子上下文，返回新的上下文和一个可设置取消原因的函数。
    * `WithDeadline()`: 创建一个带有截止时间的子上下文。
    * `WithDeadlineCause()`: 创建一个带有截止时间的子上下文，并可以设置超时原因。
    * `WithTimeout()`: 创建一个带有超时时间的子上下文（基于 `WithDeadline`）。
    * `WithTimeoutCause()`: 创建一个带有超时时间的子上下文，并可以设置超时原因。
    * `WithValue()`: 创建一个带有键值对的子上下文。
    * `WithoutCancel()`: 创建一个即使父上下文取消也不会取消的子上下文。
* **取消功能:**
    * `CancelFunc`:  一种类型，用于取消上下文。
    * `CancelCauseFunc`: 一种类型，用于取消上下文并设置取消原因。
    * 上下文取消的传播机制：当父上下文取消时，其所有子上下文也会被取消。
* **截止时间功能:** 上下文可以设置一个截止时间，到达截止时间后会自动取消。
* **键值对存储:** 上下文可以存储与请求相关的数据，这些数据可以在函数调用链中传递。
* **错误类型:** 定义了 `Canceled` 和 `DeadlineExceeded` 错误。
* **`Cause()` 函数:** 用于获取上下文取消的原因。
* **`AfterFunc()` 函数:**  在上下文被取消或超时后执行一个函数。

**3. 功能推断和代码示例：**

根据以上分析，我可以推断出以下Go语言功能是通过 `context` 包实现的：

* **请求取消和超时控制:**  这是 `context` 包最核心的功能。
    * **示例:**
        ```go
        package main

        import (
            "context"
            "fmt"
            "time"
        )

        func doWork(ctx context.Context) error {
            for i := 0; i < 10; i++ {
                select {
                case <-ctx.Done():
                    fmt.Println("任务被取消:", ctx.Err())
                    return ctx.Err()
                default:
                    fmt.Println("正在工作...", i)
                    time.Sleep(time.Second)
                }
            }
            return nil
        }

        func main() {
            ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
            defer cancel()

            fmt.Println("开始工作...")
            err := doWork(ctx)
            if err != nil {
                fmt.Println("工作完成，发生错误:", err)
            } else {
                fmt.Println("工作正常完成")
            }
        }
        // 假设输入： 无
        // 假设输出： (大约3秒后)
        // 开始工作...
        // 正在工作... 0
        // 正在工作... 1
        // 正在工作... 2
        // 任务被取消: context deadline exceeded
        // 工作完成，发生错误: context deadline exceeded
        ```

* **请求范围数据的传递:** 使用 `WithValue` 和 `Value` 方法可以在请求处理流程中传递数据。
    * **示例:**
        ```go
        package main

        import (
            "context"
            "fmt"
        )

        type UserID int

        func processRequest(ctx context.Context) {
            userID, ok := ctx.Value(UserID(1)).(UserID)
            if ok {
                fmt.Println("处理用户ID:", userID)
            } else {
                fmt.Println("未找到用户ID")
            }
        }

        func main() {
            ctx := context.WithValue(context.Background(), UserID(1), UserID(123))
            processRequest(ctx)

            ctxWithoutUser := context.Background()
            processRequest(ctxWithoutUser)
        }
        // 假设输入： 无
        // 假设输出：
        // 处理用户ID: 123
        // 未找到用户ID
        ```

* **父子上下文关系和取消传播:**  当一个父上下文被取消时，它的所有子上下文也会被取消。这在代码中通过 `propagateCancel` 方法实现。

**4. 命令行参数处理：**

`context` 包本身并不直接处理命令行参数。它的主要作用是在程序内部管理请求的上下文信息。然而，命令行参数可能会影响上下文的创建。例如，可以从命令行参数中读取超时时间，然后使用 `WithTimeout` 创建带有相应超时时间的上下文。

**示例（假设的命令行参数处理）：**

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"time"
)

var timeout = flag.Duration("timeout", 10*time.Second, "请求超时时间")

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Printf("创建了一个超时时间为 %s 的上下文\n", *timeout)

	select {
	case <-ctx.Done():
		fmt.Println("上下文已结束:", ctx.Err())
	}
}
// 运行命令： go run main.go -timeout 5s
// 输出： 创建了一个超时时间为 5s 的上下文
//       上下文已结束: context deadline exceeded
```

**5. 易犯错的点：**

* **忘记调用 `cancel` 函数:**  使用 `WithCancel`、`WithDeadline` 或 `WithTimeout` 创建的上下文会返回一个 `cancel` 函数。如果忘记调用这个函数，会导致资源泄漏（例如，goroutine 无法正常退出）。
    ```go
    // 错误示例
    func process(ctx context.Context) {
        ctxWithCancel, _ := context.WithCancel(ctx)
        // ... 在 ctxWithCancel 的上下文中执行一些操作 ...
        // 忘记调用 cancel()
    }

    // 正确示例
    func process(ctx context.Context) {
        ctxWithCancel, cancel := context.WithCancel(ctx)
        defer cancel()
        // ... 在 ctxWithCancel 的上下文中执行一些操作 ...
    }
    ```

* **在结构体中存储 `Context`:**  `Context` 应该作为函数的第一个参数显式传递，而不是存储在结构体中。这可以提高代码的清晰度和可测试性。

* **滥用 `context.Value`:** `context.Value` 应该仅用于传递请求范围内的元数据，例如请求ID、认证信息等，而不是用于传递可选参数。可选参数应该通过函数签名传递。

* **传递 `nil` `Context`:**  即使函数允许 `nil` `Context`，也应该传递 `context.TODO()` 或 `context.Background()`，以保持代码的一致性。

* **不理解取消的传播:**  开发者需要理解当父上下文取消时，所有子上下文都会被取消。这在设计并发逻辑时很重要。

通过以上分析和示例，我尽可能全面地解释了 `context.go` 的功能和使用方式，并指出了常见错误。

好的，让我们来分析一下 `go/src/context/context.go` 这个Go语言文件的功能。

**`context.go` 的主要功能：**

这个文件定义了 Go 语言中用于跨 API 边界和进程之间传递截止时间、取消信号和其他请求作用域值的 `Context` 类型及其相关功能。 它的核心作用是**管理和传播请求的上下文信息**。

更具体来说，它实现了以下功能：

1. **定义 `Context` 接口:**  这是上下文的核心抽象，定义了所有上下文类型都必须实现的方法：
    *   `Deadline()`: 返回上下文的截止时间。
    *   `Done()`: 返回一个在上下文应该被取消时关闭的只读通道。
    *   `Err()`:  如果 `Done` 通道已关闭，则返回一个非空的错误，指示取消的原因（`Canceled` 或 `DeadlineExceeded`）。
    *   `Value(key any) any`: 返回与此上下文关联的键的值。

2. **提供创建不同类型 `Context` 的函数:**
    *   **`Background()`:**  返回一个非空的、空的 `Context`。它永远不会被取消，没有值，也没有截止时间。通常用于 `main` 函数、初始化和测试，以及作为传入请求的顶级 `Context`。
    *   **`TODO()`:** 返回一个非空的、空的 `Context`。当不确定使用哪个 `Context` 时，或者周围的函数尚未扩展为接受 `Context` 参数时使用。
    *   **`WithCancel(parent Context)`:** 返回一个新的派生 `Context` 和一个 `CancelFunc`。调用 `CancelFunc` 会取消子 `Context` 及其所有派生的 `Context`。
    *   **`WithCancelCause(parent Context)`:** 类似 `WithCancel`，但返回一个 `CancelCauseFunc`，允许设置取消的原因。
    *   **`WithDeadline(parent Context, d time.Time)`:** 返回一个新的派生 `Context`，其截止时间不会晚于 `d`。
    *   **`WithDeadlineCause(parent Context, d time.Time, cause error)`:** 类似 `WithDeadline`，允许设置截止时间超过时的取消原因。
    *   **`WithTimeout(parent Context, timeout time.Duration)`:**  是 `WithDeadline` 的一个便捷封装，使用当前时间加上 `timeout` 作为截止时间。
    *   **`WithTimeoutCause(parent Context, timeout time.Duration, cause error)`:** 类似 `WithTimeout`，允许设置超时时的取消原因。
    *   **`WithValue(parent Context, key, val any)`:** 返回一个新的派生 `Context`，其中关联了一个新的键值对。

3. **实现取消机制:**
    *   当通过 `WithCancel` 或 `WithDeadline`/`WithTimeout` 创建的 `Context` 的取消函数被调用或截止时间到达时，它的 `Done()` 通道会被关闭。
    *   取消操作会传播到所有由此 `Context` 派生的子 `Context`。

4. **实现截止时间机制:**
    *   `WithDeadline` 和 `WithTimeout` 创建的 `Context` 会在指定的时间到期后自动取消。

5. **实现值传递机制:**
    *   `WithValue` 允许在 `Context` 中存储与请求相关的数据，这些数据可以通过 `Value` 方法在函数调用链中访问。

6. **提供获取取消原因的功能:**
    *   **`Cause(c Context)`:**  返回一个非空的错误，解释 `Context` `c` 被取消的原因。如果取消是通过 `CancelCauseFunc` 设置了原因，则返回该原因，否则返回 `c.Err()` 的结果。

7. **提供在上下文完成时执行函数的功能:**
    *   **`AfterFunc(ctx Context, f func())`:** 安排在 `ctx` 完成（被取消或超时）后，在一个新的 goroutine 中调用函数 `f`。

8. **定义标准错误类型:**
    *   **`Canceled`:** 当上下文被显式取消时，`Err()` 方法返回此错误。
    *   **`DeadlineExceeded`:** 当上下文的截止时间到期时，`Err()` 方法返回此错误。

**它是什么Go语言功能的实现？**

`context.go` 实现的是 Go 语言中用于**请求上下文管理和取消传播**的功能。 它允许在不同的 goroutine 和函数调用栈之间传递与特定操作相关的元数据、取消信号和截止时间。 这对于构建健壮和可取消的并发程序至关重要，特别是在处理网络请求、超时控制和资源管理等场景中。

**Go 代码示例：**

```go
package main

import (
	"context"
	"fmt"
	"time"
)

func main() {
	// 创建一个带有 2 秒超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel() // 确保在函数退出时取消上下文，释放资源

	fmt.Println("开始执行操作...")

	select {
	case <-time.After(1 * time.Second):
		fmt.Println("操作完成（在超时前）")
	case <-ctx.Done():
		fmt.Println("操作因超时而取消:", ctx.Err())
	}

	// 使用 WithValue 传递值
	ctxWithValue := context.WithValue(context.Background(), "requestID", "12345")
	printRequestID(ctxWithValue)
}

func printRequestID(ctx context.Context) {
	requestID := ctx.Value("requestID")
	fmt.Println("请求ID:", requestID)
}

// 假设输入: 无
// 假设输出 (可能因为sleep的存在而有细微差别):
// 开始执行操作...
// 操作完成（在超时前）
// 请求ID: 12345
```

**代码推理：**

在上面的示例中：

*   `context.WithTimeout` 创建了一个带有超时时间的上下文。
*   `defer cancel()` 确保了即使操作在超时前完成，也会调用 `cancel()` 来释放与上下文相关的资源。
*   `select` 语句用于模拟一个可能需要一段时间才能完成的操作。如果操作在超时前完成，则会打印 "操作完成（在超时前）"。否则，如果上下文的 `Done()` 通道被关闭（由于超时），则会打印 "操作因超时而取消..."。
*   `context.WithValue` 创建了一个新的上下文，其中关联了一个键为 "requestID"，值为 "12345" 的键值对。
*   `printRequestID` 函数通过 `ctx.Value("requestID")` 获取并打印了请求 ID。

**命令行参数的具体处理：**

`context` 包本身并不直接处理命令行参数。命令行参数的处理通常发生在应用程序的入口点（例如 `main` 函数）中，使用 `flag` 包或其他命令行解析库。

你可以使用命令行参数来影响 `Context` 的创建。例如，你可以通过命令行参数指定超时时间：

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"time"
)

var timeout = flag.Duration("timeout", 10*time.Second, "操作超时时间")

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Printf("创建了一个超时时间为 %s 的上下文\n", *timeout)

	select {
	case <-time.After(5 * time.Second):
		fmt.Println("操作完成")
	case <-ctx.Done():
		fmt.Println("操作因超时而取消:", ctx.Err())
	}
}

// 运行命令: go run main.go -timeout 5s
// 输出:
// 创建了一个超时时间为 5s 的上下文
// 操作完成

// 运行命令: go run main.go -timeout 2s
// 输出:
// 创建了一个超时时间为 2s 的上下文
// 操作因超时而取消: context deadline exceeded
```

在这个例子中，`flag.Duration` 定义了一个名为 `timeout` 的命令行参数，默认值为 10 秒。程序根据传入的命令行参数值创建具有相应超时时间的 `Context`。

**使用者易犯错的点：**

1. **忘记调用 `cancel` 函数:** 当使用 `WithCancel`、`WithDeadline` 或 `WithTimeout` 创建上下文时，会返回一个 `cancel` 函数。**必须**在不再需要该上下文时调用 `cancel()` 来释放资源，否则可能会导致 goroutine 泄漏或其他问题。通常使用 `defer cancel()` 来确保调用。

    ```go
    // 错误示例
    func doSomething(parent context.Context) {
        ctx, _ := context.WithCancel(parent)
        // ... 使用 ctx ...
        // 忘记调用 cancel()
    }

    // 正确示例
    func doSomething(parent context.Context) {
        ctx, cancel := context.WithCancel(parent)
        defer cancel()
        // ... 使用 ctx ...
    }
    ```

2. **在结构体中存储 `Context`:**  `Context` 应该作为函数的第一个参数显式传递，而不是存储在结构体中。这是 Go 官方推荐的做法，可以提高代码的清晰度和可测试性。

    ```go
    // 错误示例
    type MyService struct {
        ctx context.Context
    }

    func (s *MyService) DoSomething() {
        // 使用 s.ctx
    }

    // 正确示例
    type MyService struct {
        // ... 其他字段 ...
    }

    func (s *MyService) DoSomething(ctx context.Context) {
        // 使用传入的 ctx
    }
    ```

3. **滥用 `context.Value`:**  `context.Value` 应该仅用于传递请求作用域的元数据，例如请求 ID、认证信息等。不应该用于传递函数的可选参数。可选参数应该通过函数签名传递。

4. **传递 `nil` `Context`:**  即使函数签名允许 `nil` `Context`，也应该传递 `context.TODO()` 或 `context.Background()`，以保持代码的一致性。

希望这个详细的解释能够帮助你理解 `go/src/context/context.go` 的功能。

Prompt: 
```
这是路径为go/src/context/context.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package context defines the Context type, which carries deadlines,
// cancellation signals, and other request-scoped values across API boundaries
// and between processes.
//
// Incoming requests to a server should create a [Context], and outgoing
// calls to servers should accept a Context. The chain of function
// calls between them must propagate the Context, optionally replacing
// it with a derived Context created using [WithCancel], [WithDeadline],
// [WithTimeout], or [WithValue]. When a Context is canceled, all
// Contexts derived from it are also canceled.
//
// The [WithCancel], [WithDeadline], and [WithTimeout] functions take a
// Context (the parent) and return a derived Context (the child) and a
// [CancelFunc]. Calling the CancelFunc cancels the child and its
// children, removes the parent's reference to the child, and stops
// any associated timers. Failing to call the CancelFunc leaks the
// child and its children until the parent is canceled or the timer
// fires. The go vet tool checks that CancelFuncs are used on all
// control-flow paths.
//
// The [WithCancelCause] function returns a [CancelCauseFunc], which
// takes an error and records it as the cancellation cause. Calling
// [Cause] on the canceled context or any of its children retrieves
// the cause. If no cause is specified, Cause(ctx) returns the same
// value as ctx.Err().
//
// Programs that use Contexts should follow these rules to keep interfaces
// consistent across packages and enable static analysis tools to check context
// propagation:
//
// Do not store Contexts inside a struct type; instead, pass a Context
// explicitly to each function that needs it. This is discussed further in
// https://go.dev/blog/context-and-structs. The Context should be the first
// parameter, typically named ctx:
//
//	func DoSomething(ctx context.Context, arg Arg) error {
//		// ... use ctx ...
//	}
//
// Do not pass a nil [Context], even if a function permits it. Pass [context.TODO]
// if you are unsure about which Context to use.
//
// Use context Values only for request-scoped data that transits processes and
// APIs, not for passing optional parameters to functions.
//
// The same Context may be passed to functions running in different goroutines;
// Contexts are safe for simultaneous use by multiple goroutines.
//
// See https://go.dev/blog/context for example code for a server that uses
// Contexts.
package context

import (
	"errors"
	"internal/reflectlite"
	"sync"
	"sync/atomic"
	"time"
)

// A Context carries a deadline, a cancellation signal, and other values across
// API boundaries.
//
// Context's methods may be called by multiple goroutines simultaneously.
type Context interface {
	// Deadline returns the time when work done on behalf of this context
	// should be canceled. Deadline returns ok==false when no deadline is
	// set. Successive calls to Deadline return the same results.
	Deadline() (deadline time.Time, ok bool)

	// Done returns a channel that's closed when work done on behalf of this
	// context should be canceled. Done may return nil if this context can
	// never be canceled. Successive calls to Done return the same value.
	// The close of the Done channel may happen asynchronously,
	// after the cancel function returns.
	//
	// WithCancel arranges for Done to be closed when cancel is called;
	// WithDeadline arranges for Done to be closed when the deadline
	// expires; WithTimeout arranges for Done to be closed when the timeout
	// elapses.
	//
	// Done is provided for use in select statements:
	//
	//  // Stream generates values with DoSomething and sends them to out
	//  // until DoSomething returns an error or ctx.Done is closed.
	//  func Stream(ctx context.Context, out chan<- Value) error {
	//  	for {
	//  		v, err := DoSomething(ctx)
	//  		if err != nil {
	//  			return err
	//  		}
	//  		select {
	//  		case <-ctx.Done():
	//  			return ctx.Err()
	//  		case out <- v:
	//  		}
	//  	}
	//  }
	//
	// See https://blog.golang.org/pipelines for more examples of how to use
	// a Done channel for cancellation.
	Done() <-chan struct{}

	// If Done is not yet closed, Err returns nil.
	// If Done is closed, Err returns a non-nil error explaining why:
	// Canceled if the context was canceled
	// or DeadlineExceeded if the context's deadline passed.
	// After Err returns a non-nil error, successive calls to Err return the same error.
	Err() error

	// Value returns the value associated with this context for key, or nil
	// if no value is associated with key. Successive calls to Value with
	// the same key returns the same result.
	//
	// Use context values only for request-scoped data that transits
	// processes and API boundaries, not for passing optional parameters to
	// functions.
	//
	// A key identifies a specific value in a Context. Functions that wish
	// to store values in Context typically allocate a key in a global
	// variable then use that key as the argument to context.WithValue and
	// Context.Value. A key can be any type that supports equality;
	// packages should define keys as an unexported type to avoid
	// collisions.
	//
	// Packages that define a Context key should provide type-safe accessors
	// for the values stored using that key:
	//
	// 	// Package user defines a User type that's stored in Contexts.
	// 	package user
	//
	// 	import "context"
	//
	// 	// User is the type of value stored in the Contexts.
	// 	type User struct {...}
	//
	// 	// key is an unexported type for keys defined in this package.
	// 	// This prevents collisions with keys defined in other packages.
	// 	type key int
	//
	// 	// userKey is the key for user.User values in Contexts. It is
	// 	// unexported; clients use user.NewContext and user.FromContext
	// 	// instead of using this key directly.
	// 	var userKey key
	//
	// 	// NewContext returns a new Context that carries value u.
	// 	func NewContext(ctx context.Context, u *User) context.Context {
	// 		return context.WithValue(ctx, userKey, u)
	// 	}
	//
	// 	// FromContext returns the User value stored in ctx, if any.
	// 	func FromContext(ctx context.Context) (*User, bool) {
	// 		u, ok := ctx.Value(userKey).(*User)
	// 		return u, ok
	// 	}
	Value(key any) any
}

// Canceled is the error returned by [Context.Err] when the context is canceled.
var Canceled = errors.New("context canceled")

// DeadlineExceeded is the error returned by [Context.Err] when the context's
// deadline passes.
var DeadlineExceeded error = deadlineExceededError{}

type deadlineExceededError struct{}

func (deadlineExceededError) Error() string   { return "context deadline exceeded" }
func (deadlineExceededError) Timeout() bool   { return true }
func (deadlineExceededError) Temporary() bool { return true }

// An emptyCtx is never canceled, has no values, and has no deadline.
// It is the common base of backgroundCtx and todoCtx.
type emptyCtx struct{}

func (emptyCtx) Deadline() (deadline time.Time, ok bool) {
	return
}

func (emptyCtx) Done() <-chan struct{} {
	return nil
}

func (emptyCtx) Err() error {
	return nil
}

func (emptyCtx) Value(key any) any {
	return nil
}

type backgroundCtx struct{ emptyCtx }

func (backgroundCtx) String() string {
	return "context.Background"
}

type todoCtx struct{ emptyCtx }

func (todoCtx) String() string {
	return "context.TODO"
}

// Background returns a non-nil, empty [Context]. It is never canceled, has no
// values, and has no deadline. It is typically used by the main function,
// initialization, and tests, and as the top-level Context for incoming
// requests.
func Background() Context {
	return backgroundCtx{}
}

// TODO returns a non-nil, empty [Context]. Code should use context.TODO when
// it's unclear which Context to use or it is not yet available (because the
// surrounding function has not yet been extended to accept a Context
// parameter).
func TODO() Context {
	return todoCtx{}
}

// A CancelFunc tells an operation to abandon its work.
// A CancelFunc does not wait for the work to stop.
// A CancelFunc may be called by multiple goroutines simultaneously.
// After the first call, subsequent calls to a CancelFunc do nothing.
type CancelFunc func()

// WithCancel returns a derived context that points to the parent context
// but has a new Done channel. The returned context's Done channel is closed
// when the returned cancel function is called or when the parent context's
// Done channel is closed, whichever happens first.
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this [Context] complete.
func WithCancel(parent Context) (ctx Context, cancel CancelFunc) {
	c := withCancel(parent)
	return c, func() { c.cancel(true, Canceled, nil) }
}

// A CancelCauseFunc behaves like a [CancelFunc] but additionally sets the cancellation cause.
// This cause can be retrieved by calling [Cause] on the canceled Context or on
// any of its derived Contexts.
//
// If the context has already been canceled, CancelCauseFunc does not set the cause.
// For example, if childContext is derived from parentContext:
//   - if parentContext is canceled with cause1 before childContext is canceled with cause2,
//     then Cause(parentContext) == Cause(childContext) == cause1
//   - if childContext is canceled with cause2 before parentContext is canceled with cause1,
//     then Cause(parentContext) == cause1 and Cause(childContext) == cause2
type CancelCauseFunc func(cause error)

// WithCancelCause behaves like [WithCancel] but returns a [CancelCauseFunc] instead of a [CancelFunc].
// Calling cancel with a non-nil error (the "cause") records that error in ctx;
// it can then be retrieved using Cause(ctx).
// Calling cancel with nil sets the cause to Canceled.
//
// Example use:
//
//	ctx, cancel := context.WithCancelCause(parent)
//	cancel(myError)
//	ctx.Err() // returns context.Canceled
//	context.Cause(ctx) // returns myError
func WithCancelCause(parent Context) (ctx Context, cancel CancelCauseFunc) {
	c := withCancel(parent)
	return c, func(cause error) { c.cancel(true, Canceled, cause) }
}

func withCancel(parent Context) *cancelCtx {
	if parent == nil {
		panic("cannot create context from nil parent")
	}
	c := &cancelCtx{}
	c.propagateCancel(parent, c)
	return c
}

// Cause returns a non-nil error explaining why c was canceled.
// The first cancellation of c or one of its parents sets the cause.
// If that cancellation happened via a call to CancelCauseFunc(err),
// then [Cause] returns err.
// Otherwise Cause(c) returns the same value as c.Err().
// Cause returns nil if c has not been canceled yet.
func Cause(c Context) error {
	if cc, ok := c.Value(&cancelCtxKey).(*cancelCtx); ok {
		cc.mu.Lock()
		defer cc.mu.Unlock()
		return cc.cause
	}
	// There is no cancelCtxKey value, so we know that c is
	// not a descendant of some Context created by WithCancelCause.
	// Therefore, there is no specific cause to return.
	// If this is not one of the standard Context types,
	// it might still have an error even though it won't have a cause.
	return c.Err()
}

// AfterFunc arranges to call f in its own goroutine after ctx is done
// (canceled or timed out).
// If ctx is already done, AfterFunc calls f immediately in its own goroutine.
//
// Multiple calls to AfterFunc on a context operate independently;
// one does not replace another.
//
// Calling the returned stop function stops the association of ctx with f.
// It returns true if the call stopped f from being run.
// If stop returns false,
// either the context is done and f has been started in its own goroutine;
// or f was already stopped.
// The stop function does not wait for f to complete before returning.
// If the caller needs to know whether f is completed,
// it must coordinate with f explicitly.
//
// If ctx has a "AfterFunc(func()) func() bool" method,
// AfterFunc will use it to schedule the call.
func AfterFunc(ctx Context, f func()) (stop func() bool) {
	a := &afterFuncCtx{
		f: f,
	}
	a.cancelCtx.propagateCancel(ctx, a)
	return func() bool {
		stopped := false
		a.once.Do(func() {
			stopped = true
		})
		if stopped {
			a.cancel(true, Canceled, nil)
		}
		return stopped
	}
}

type afterFuncer interface {
	AfterFunc(func()) func() bool
}

type afterFuncCtx struct {
	cancelCtx
	once sync.Once // either starts running f or stops f from running
	f    func()
}

func (a *afterFuncCtx) cancel(removeFromParent bool, err, cause error) {
	a.cancelCtx.cancel(false, err, cause)
	if removeFromParent {
		removeChild(a.Context, a)
	}
	a.once.Do(func() {
		go a.f()
	})
}

// A stopCtx is used as the parent context of a cancelCtx when
// an AfterFunc has been registered with the parent.
// It holds the stop function used to unregister the AfterFunc.
type stopCtx struct {
	Context
	stop func() bool
}

// goroutines counts the number of goroutines ever created; for testing.
var goroutines atomic.Int32

// &cancelCtxKey is the key that a cancelCtx returns itself for.
var cancelCtxKey int

// parentCancelCtx returns the underlying *cancelCtx for parent.
// It does this by looking up parent.Value(&cancelCtxKey) to find
// the innermost enclosing *cancelCtx and then checking whether
// parent.Done() matches that *cancelCtx. (If not, the *cancelCtx
// has been wrapped in a custom implementation providing a
// different done channel, in which case we should not bypass it.)
func parentCancelCtx(parent Context) (*cancelCtx, bool) {
	done := parent.Done()
	if done == closedchan || done == nil {
		return nil, false
	}
	p, ok := parent.Value(&cancelCtxKey).(*cancelCtx)
	if !ok {
		return nil, false
	}
	pdone, _ := p.done.Load().(chan struct{})
	if pdone != done {
		return nil, false
	}
	return p, true
}

// removeChild removes a context from its parent.
func removeChild(parent Context, child canceler) {
	if s, ok := parent.(stopCtx); ok {
		s.stop()
		return
	}
	p, ok := parentCancelCtx(parent)
	if !ok {
		return
	}
	p.mu.Lock()
	if p.children != nil {
		delete(p.children, child)
	}
	p.mu.Unlock()
}

// A canceler is a context type that can be canceled directly. The
// implementations are *cancelCtx and *timerCtx.
type canceler interface {
	cancel(removeFromParent bool, err, cause error)
	Done() <-chan struct{}
}

// closedchan is a reusable closed channel.
var closedchan = make(chan struct{})

func init() {
	close(closedchan)
}

// A cancelCtx can be canceled. When canceled, it also cancels any children
// that implement canceler.
type cancelCtx struct {
	Context

	mu       sync.Mutex            // protects following fields
	done     atomic.Value          // of chan struct{}, created lazily, closed by first cancel call
	children map[canceler]struct{} // set to nil by the first cancel call
	err      error                 // set to non-nil by the first cancel call
	cause    error                 // set to non-nil by the first cancel call
}

func (c *cancelCtx) Value(key any) any {
	if key == &cancelCtxKey {
		return c
	}
	return value(c.Context, key)
}

func (c *cancelCtx) Done() <-chan struct{} {
	d := c.done.Load()
	if d != nil {
		return d.(chan struct{})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	d = c.done.Load()
	if d == nil {
		d = make(chan struct{})
		c.done.Store(d)
	}
	return d.(chan struct{})
}

func (c *cancelCtx) Err() error {
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	return err
}

// propagateCancel arranges for child to be canceled when parent is.
// It sets the parent context of cancelCtx.
func (c *cancelCtx) propagateCancel(parent Context, child canceler) {
	c.Context = parent

	done := parent.Done()
	if done == nil {
		return // parent is never canceled
	}

	select {
	case <-done:
		// parent is already canceled
		child.cancel(false, parent.Err(), Cause(parent))
		return
	default:
	}

	if p, ok := parentCancelCtx(parent); ok {
		// parent is a *cancelCtx, or derives from one.
		p.mu.Lock()
		if p.err != nil {
			// parent has already been canceled
			child.cancel(false, p.err, p.cause)
		} else {
			if p.children == nil {
				p.children = make(map[canceler]struct{})
			}
			p.children[child] = struct{}{}
		}
		p.mu.Unlock()
		return
	}

	if a, ok := parent.(afterFuncer); ok {
		// parent implements an AfterFunc method.
		c.mu.Lock()
		stop := a.AfterFunc(func() {
			child.cancel(false, parent.Err(), Cause(parent))
		})
		c.Context = stopCtx{
			Context: parent,
			stop:    stop,
		}
		c.mu.Unlock()
		return
	}

	goroutines.Add(1)
	go func() {
		select {
		case <-parent.Done():
			child.cancel(false, parent.Err(), Cause(parent))
		case <-child.Done():
		}
	}()
}

type stringer interface {
	String() string
}

func contextName(c Context) string {
	if s, ok := c.(stringer); ok {
		return s.String()
	}
	return reflectlite.TypeOf(c).String()
}

func (c *cancelCtx) String() string {
	return contextName(c.Context) + ".WithCancel"
}

// cancel closes c.done, cancels each of c's children, and, if
// removeFromParent is true, removes c from its parent's children.
// cancel sets c.cause to cause if this is the first time c is canceled.
func (c *cancelCtx) cancel(removeFromParent bool, err, cause error) {
	if err == nil {
		panic("context: internal error: missing cancel error")
	}
	if cause == nil {
		cause = err
	}
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return // already canceled
	}
	c.err = err
	c.cause = cause
	d, _ := c.done.Load().(chan struct{})
	if d == nil {
		c.done.Store(closedchan)
	} else {
		close(d)
	}
	for child := range c.children {
		// NOTE: acquiring the child's lock while holding parent's lock.
		child.cancel(false, err, cause)
	}
	c.children = nil
	c.mu.Unlock()

	if removeFromParent {
		removeChild(c.Context, c)
	}
}

// WithoutCancel returns a derived context that points to the parent context
// and is not canceled when parent is canceled.
// The returned context returns no Deadline or Err, and its Done channel is nil.
// Calling [Cause] on the returned context returns nil.
func WithoutCancel(parent Context) Context {
	if parent == nil {
		panic("cannot create context from nil parent")
	}
	return withoutCancelCtx{parent}
}

type withoutCancelCtx struct {
	c Context
}

func (withoutCancelCtx) Deadline() (deadline time.Time, ok bool) {
	return
}

func (withoutCancelCtx) Done() <-chan struct{} {
	return nil
}

func (withoutCancelCtx) Err() error {
	return nil
}

func (c withoutCancelCtx) Value(key any) any {
	return value(c, key)
}

func (c withoutCancelCtx) String() string {
	return contextName(c.c) + ".WithoutCancel"
}

// WithDeadline returns a derived context that points to the parent context
// but has the deadline adjusted to be no later than d. If the parent's
// deadline is already earlier than d, WithDeadline(parent, d) is semantically
// equivalent to parent. The returned [Context.Done] channel is closed when
// the deadline expires, when the returned cancel function is called,
// or when the parent context's Done channel is closed, whichever happens first.
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this [Context] complete.
func WithDeadline(parent Context, d time.Time) (Context, CancelFunc) {
	return WithDeadlineCause(parent, d, nil)
}

// WithDeadlineCause behaves like [WithDeadline] but also sets the cause of the
// returned Context when the deadline is exceeded. The returned [CancelFunc] does
// not set the cause.
func WithDeadlineCause(parent Context, d time.Time, cause error) (Context, CancelFunc) {
	if parent == nil {
		panic("cannot create context from nil parent")
	}
	if cur, ok := parent.Deadline(); ok && cur.Before(d) {
		// The current deadline is already sooner than the new one.
		return WithCancel(parent)
	}
	c := &timerCtx{
		deadline: d,
	}
	c.cancelCtx.propagateCancel(parent, c)
	dur := time.Until(d)
	if dur <= 0 {
		c.cancel(true, DeadlineExceeded, cause) // deadline has already passed
		return c, func() { c.cancel(false, Canceled, nil) }
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.timer = time.AfterFunc(dur, func() {
			c.cancel(true, DeadlineExceeded, cause)
		})
	}
	return c, func() { c.cancel(true, Canceled, nil) }
}

// A timerCtx carries a timer and a deadline. It embeds a cancelCtx to
// implement Done and Err. It implements cancel by stopping its timer then
// delegating to cancelCtx.cancel.
type timerCtx struct {
	cancelCtx
	timer *time.Timer // Under cancelCtx.mu.

	deadline time.Time
}

func (c *timerCtx) Deadline() (deadline time.Time, ok bool) {
	return c.deadline, true
}

func (c *timerCtx) String() string {
	return contextName(c.cancelCtx.Context) + ".WithDeadline(" +
		c.deadline.String() + " [" +
		time.Until(c.deadline).String() + "])"
}

func (c *timerCtx) cancel(removeFromParent bool, err, cause error) {
	c.cancelCtx.cancel(false, err, cause)
	if removeFromParent {
		// Remove this timerCtx from its parent cancelCtx's children.
		removeChild(c.cancelCtx.Context, c)
	}
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
}

// WithTimeout returns WithDeadline(parent, time.Now().Add(timeout)).
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this [Context] complete:
//
//	func slowOperationWithTimeout(ctx context.Context) (Result, error) {
//		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
//		defer cancel()  // releases resources if slowOperation completes before timeout elapses
//		return slowOperation(ctx)
//	}
func WithTimeout(parent Context, timeout time.Duration) (Context, CancelFunc) {
	return WithDeadline(parent, time.Now().Add(timeout))
}

// WithTimeoutCause behaves like [WithTimeout] but also sets the cause of the
// returned Context when the timeout expires. The returned [CancelFunc] does
// not set the cause.
func WithTimeoutCause(parent Context, timeout time.Duration, cause error) (Context, CancelFunc) {
	return WithDeadlineCause(parent, time.Now().Add(timeout), cause)
}

// WithValue returns a derived context that points to the parent Context.
// In the derived context, the value associated with key is val.
//
// Use context Values only for request-scoped data that transits processes and
// APIs, not for passing optional parameters to functions.
//
// The provided key must be comparable and should not be of type
// string or any other built-in type to avoid collisions between
// packages using context. Users of WithValue should define their own
// types for keys. To avoid allocating when assigning to an
// interface{}, context keys often have concrete type
// struct{}. Alternatively, exported context key variables' static
// type should be a pointer or interface.
func WithValue(parent Context, key, val any) Context {
	if parent == nil {
		panic("cannot create context from nil parent")
	}
	if key == nil {
		panic("nil key")
	}
	if !reflectlite.TypeOf(key).Comparable() {
		panic("key is not comparable")
	}
	return &valueCtx{parent, key, val}
}

// A valueCtx carries a key-value pair. It implements Value for that key and
// delegates all other calls to the embedded Context.
type valueCtx struct {
	Context
	key, val any
}

// stringify tries a bit to stringify v, without using fmt, since we don't
// want context depending on the unicode tables. This is only used by
// *valueCtx.String().
func stringify(v any) string {
	switch s := v.(type) {
	case stringer:
		return s.String()
	case string:
		return s
	case nil:
		return "<nil>"
	}
	return reflectlite.TypeOf(v).String()
}

func (c *valueCtx) String() string {
	return contextName(c.Context) + ".WithValue(" +
		stringify(c.key) + ", " +
		stringify(c.val) + ")"
}

func (c *valueCtx) Value(key any) any {
	if c.key == key {
		return c.val
	}
	return value(c.Context, key)
}

func value(c Context, key any) any {
	for {
		switch ctx := c.(type) {
		case *valueCtx:
			if key == ctx.key {
				return ctx.val
			}
			c = ctx.Context
		case *cancelCtx:
			if key == &cancelCtxKey {
				return c
			}
			c = ctx.Context
		case withoutCancelCtx:
			if key == &cancelCtxKey {
				// This implements Cause(ctx) == nil
				// when ctx is created using WithoutCancel.
				return nil
			}
			c = ctx.c
		case *timerCtx:
			if key == &cancelCtxKey {
				return &ctx.cancelCtx
			}
			c = ctx.Context
		case backgroundCtx, todoCtx:
			return nil
		default:
			return c.Value(key)
		}
	}
}

"""



```