Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - What is the Core Functionality?**

The first thing that jumps out is the repeated use of `ioctl`. Even without prior knowledge, the name `IoctlRetInt`, `IoctlGetUint32`, etc., strongly suggests interaction with the operating system's input/output control mechanism. The package name `unix` reinforces this. Therefore, the core functionality is clearly about making `ioctl` system calls.

**2. Dissecting the `ioctl` Functions:**

* **`IoctlRetInt(fd int, req uint) (int, error)`:** This is the most basic `ioctl` wrapper. It takes a file descriptor (`fd`) and a request code (`req`), makes the `SYS_IOCTL` syscall, and returns the integer result and any error. The `0` as the third argument in `Syscall` hints at a simpler `ioctl` where no data is being passed directly.

* **`ioctlPtr(fd int, req uint, data unsafe.Pointer) error`:** This is a helper function used by most of the other `Ioctl` functions. It encapsulates the `SYS_IOCTL` syscall with a pointer to data. This suggests that many `ioctl` calls involve passing data structures to the kernel.

* **Specialized `IoctlGet...` and `IoctlSet...` functions:**  These immediately indicate specific `ioctl` commands. The names (`IoctlGetRTCTime`, `IoctlSetRTCWkAlrm`, `IoctlGetEthtoolDrvinfo`, etc.) suggest the *kinds* of operations being performed (getting/setting RTC time, network interface information, etc.).

**3. Identifying Specific Go Features:**

* **`unsafe.Pointer`:** The frequent use of `unsafe.Pointer` is a key indicator of low-level system interaction. `ioctl` often requires passing raw memory addresses to the kernel. This immediately flags this code as dealing with system calls and potentially manipulating memory layouts directly.

* **Structures (`RTCTime`, `RTCWkAlrm`, `EthtoolDrvinfo`, etc.):** These structures represent the data exchanged with the kernel via `ioctl`. The `IoctlGet...` functions will often populate these structures with data from the kernel, and `IoctlSet...` functions will pass populated structures to the kernel.

* **`Syscall`:** The `Syscall` function from the `syscall` package (imported implicitly) is the direct way to invoke system calls in Go. This confirms the low-level nature of the code.

* **String Handling (`ifname string`, `ByteSliceToString`):**  The presence of string parameters, particularly related to network interfaces (`ifname`), suggests interaction with network devices. The `ByteSliceToString` function hints at converting C-style fixed-size character arrays from the kernel into Go strings.

**4. Inferring the Purpose and Examples:**

By looking at the specific `ioctl` requests (even without knowing the exact values of constants like `RTC_RD_TIME`, `ETHTOOL_GDRVINFO`, etc.), you can infer the high-level purpose:

* **Real-Time Clock (RTC):** Functions like `IoctlGetRTCTime` and `IoctlSetRTCTime` clearly deal with getting and setting the hardware clock.
* **Network Devices (Ethtool, HwTstamp):** Functions with names like `IoctlGetEthtoolDrvinfo`, `IoctlSetHwTstamp` point to interacting with network interface configurations and retrieving information.
* **PTP (Precision Time Protocol):** The `IoctlPtp...` functions deal with PTP hardware, likely for precise time synchronization.
* **Watchdog Timer:** `IoctlGetWatchdogInfo` and `IoctlWatchdogKeepalive` are clearly for interacting with a hardware watchdog timer.
* **File Cloning and Deduplication:**  `IoctlFileCloneRange`, `IoctlFileClone`, and `IoctlFileDedupeRange` relate to advanced file system operations.
* **HID (Human Interface Devices):**  The `IoctlHIDGet...` functions retrieve information about HID devices.
* **Network Interface Configuration (Ifreq):** `IoctlIfreq` is a general function for network interface configuration.
* **KCM (Kernel Connection Multiplexor):**  `IoctlKCMClone`, `IoctlKCMAttach`, `IoctlKCMUnattach` are related to managing multiplexed network connections.
* **Loop Devices:** `IoctlLoopGetStatus64`, `IoctlLoopSetStatus64`, `IoctlLoopConfigure` deal with managing loopback devices.

Based on these inferences, constructing example code becomes straightforward. For example, to demonstrate getting the RTC time, you'd need to open the RTC device, call `IoctlGetRTCTime`, and then access the fields of the returned `RTCTime` struct.

**5. Identifying Potential Pitfalls:**

The use of `unsafe.Pointer` is the biggest red flag for potential errors. Incorrectly sized structures, wrong offsets, or memory corruption are common issues when working with raw pointers. The need to open the correct device file descriptor (`/dev/rtc0`, network interface, etc.) is another potential source of error. Also, the specific `ioctl` request codes and the structure layouts are platform-dependent, which could lead to portability issues if not handled carefully.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just wrapping system calls."
* **Refinement:** "It's wrapping *specific* `ioctl` system calls related to various hardware and kernel subsystems."
* **Initial thought:** "The examples are complex."
* **Refinement:** "Focus on the core steps: opening a file descriptor, calling the `Ioctl` function, and interpreting the result."

By following this systematic approach, we can effectively analyze and understand the functionality of the provided Go code, even without prior knowledge of the specific `ioctl` commands. The key is to recognize the patterns, the use of low-level features, and the naming conventions of the functions.
这段 Go 语言代码是 `golang.org/x/sys/unix` 包中用于执行 `ioctl` 系统调用的部分，它为 Linux 系统上的各种设备和子系统提供了更便捷的 Go 接口。`ioctl` (input/output control) 是一种强大的系统调用，允许用户空间程序与设备驱动程序进行交互，执行设备特定的操作。

以下是这段代码中各个函数的功能：

**核心功能:**

* **`IoctlRetInt(fd int, req uint) (int, error)`:**
    * 执行一个由 `req` 指定的 `ioctl` 操作，操作的设备与文件描述符 `fd` 关联。
    * 返回 `ioctl` 系统调用返回的非负整数结果。
    * 用于那些 `ioctl` 操作主要返回一个整数值的场景。

* **`ioctlPtr(fd int, req uint, data unsafe.Pointer) error`:**
    * 这是一个内部辅助函数，用于执行需要传递数据指针的 `ioctl` 操作。
    * `data` 参数是指向要传递给 `ioctl` 或从 `ioctl` 接收的数据的指针。
    * 大部分其他的 `Ioctl...` 函数都基于这个函数构建。

**特定设备或子系统的功能:**

* **实时时钟 (RTC):**
    * **`IoctlGetRTCTime(fd int) (*RTCTime, error)`:**  获取 RTC 设备的当前时间。
    * **`IoctlSetRTCTime(fd int, value *RTCTime) error`:** 设置 RTC 设备的时间。
    * **`IoctlGetRTCWkAlrm(fd int) (*RTCWkAlrm, error)`:** 获取 RTC 设备的唤醒闹钟设置。
    * **`IoctlSetRTCWkAlrm(fd int, value *RTCWkAlrm) error`:** 设置 RTC 设备的唤醒闹钟。

* **网络设备 (Ethtool, Hardware Timestamping):**
    * **`IoctlGetEthtoolDrvinfo(fd int, ifname string) (*EthtoolDrvinfo, error)`:** 获取指定网络设备接口 (`ifname`) 的 ethtool 驱动信息。
    * **`IoctlGetEthtoolTsInfo(fd int, ifname string) (*EthtoolTsInfo, error)`:** 获取指定网络设备接口的时间戳信息和 PHC (Precision Hardware Clock) 关联信息。
    * **`IoctlGetHwTstamp(fd int, ifname string) (*HwTstampConfig, error)`:** 获取指定网络设备接口的硬件时间戳配置。
    * **`IoctlSetHwTstamp(fd int, ifname string, cfg *HwTstampConfig) error`:** 设置指定网络设备接口的硬件时间戳配置。

* **PTP (Precision Time Protocol) 时钟:**
    * **`FdToClockID(fd int) int32`:**  从文件描述符派生出时钟 ID，用于 `clock_gettime` 等系统调用。
    * **`IoctlPtpClockGetcaps(fd int) (*PtpClockCaps, error)`:** 获取 PTP 设备的描述信息。
    * **`IoctlPtpSysOffsetPrecise(fd int) (*PtpSysOffsetPrecise, error)`:** 获取 PTP 时钟相对于系统时钟的精确偏移量。
    * **`IoctlPtpSysOffsetExtended(fd int, samples uint) (*PtpSysOffsetExtended, error)`:** 获取 PTP 时钟相对于系统时钟的扩展偏移量，可以指定采样数。
    * **`IoctlPtpPinGetfunc(fd int, index uint) (*PtpPinDesc, error)`:** 获取 PTP 设备上指定 I/O 引脚的配置。
    * **`IoctlPtpPinSetfunc(fd int, pd *PtpPinDesc) error`:** 设置 PTP 设备上指定 I/O 引脚的配置。
    * **`IoctlPtpPeroutRequest(fd int, r *PtpPeroutRequest) error`:** 配置 PTP I/O 引脚的周期性输出模式。
    * **`IoctlPtpExttsRequest(fd int, r *PtpExttsRequest) error`:** 配置 PTP I/O 引脚的外部时间戳模式。

* **看门狗 (Watchdog):**
    * **`IoctlGetWatchdogInfo(fd int) (*WatchdogInfo, error)`:** 获取看门狗设备的信息。
    * **`IoctlWatchdogKeepalive(fd int) error`:** 向看门狗设备发送保活信号，防止系统重启。

* **文件克隆和去重:**
    * **`IoctlFileCloneRange(destFd int, value *FileCloneRange) error`:** 使用 `FICLONERANGE` ioctl 操作克隆文件指定范围的数据。
    * **`IoctlFileClone(destFd, srcFd int) error`:** 使用 `FICLONE` ioctl 操作克隆整个文件。
    * **`IoctlFileDedupeRange(srcFd int, value *FileDedupeRange) error`:** 使用 `FIDEDUPERANGE` ioctl 操作在多个文件中共享相同的数据块 (去重)。

* **HID (Human Interface Devices):**
    * **`IoctlHIDGetDesc(fd int, value *HIDRawReportDescriptor) error`:** 获取 HID 设备的报告描述符。
    * **`IoctlHIDGetRawInfo(fd int) (*HIDRawDevInfo, error)`:** 获取 HID 设备的原始信息。
    * **`IoctlHIDGetRawName(fd int) (string, error)`:** 获取 HID 设备的名称。
    * **`IoctlHIDGetRawPhys(fd int) (string, error)`:** 获取 HID 设备的物理路径。
    * **`IoctlHIDGetRawUniq(fd int) (string, error)`:** 获取 HID 设备的唯一标识符。

* **网络接口配置 (通用):**
    * **`IoctlIfreq(fd int, req uint, value *Ifreq) error`:** 执行一个使用 `Ifreq` 结构体的 `ioctl` 操作，用于网络接口的配置。
    * **`ioctlIfreqData(fd int, req uint, value *ifreqData) error`:** 类似于 `IoctlIfreq`，但可能使用内部的 `ifreqData` 结构体。

* **KCM (Kernel Connection Multiplexor):**
    * **`IoctlKCMClone(fd int) (*KCMClone, error)`:** 克隆一个现有的 KCM 套接字，创建一个新的文件描述符。
    * **`IoctlKCMAttach(fd int, info KCMAttach) error`:** 将一个 TCP 套接字和相关的 BPF 程序文件描述符附加到 KCM。
    * **`IoctlKCMUnattach(fd int, info KCMUnattach) error`:** 从 KCM 解除一个 TCP 套接字文件描述符的附加。

* **Loop 设备:**
    * **`IoctlLoopGetStatus64(fd int) (*LoopInfo64, error)`:** 获取与文件描述符关联的 loop 设备的状态。
    * **`IoctlLoopSetStatus64(fd int, value *LoopInfo64) error`:** 设置 loop 设备的状态。
    * **`IoctlLoopConfigure(fd int, value *LoopConfig) error`:**  一步配置所有的 loop 设备参数。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言中与 Linux 内核进行底层交互的一种方式的实现。它封装了 `ioctl` 系统调用，使得 Go 程序可以执行各种设备特定的操作，而无需直接使用 C 语言的接口。它利用了 Go 的 `syscall` 包来执行系统调用，并使用 `unsafe` 包来处理与 C 结构体内存布局的交互。

**Go 代码示例:**

假设我们要获取 RTC 设备的当前时间：

```go
package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	fd, err := os.Open("/dev/rtc0") // 假设 /dev/rtc0 是 RTC 设备的文件路径
	if err != nil {
		fmt.Println("Error opening RTC device:", err)
		return
	}
	defer fd.Close()

	rtcTime, err := unix.IoctlGetRTCTime(int(fd.Fd()))
	if err != nil {
		fmt.Println("Error getting RTC time:", err)
		return
	}

	// unix.RTCTime 结构体中的字段对应内核 rtc_time 结构体
	goTime := time.Date(
		int(rtcTime.Year)+1900, // RTC 的 year 从 0 开始，表示从 1900 年开始的年份
		time.Month(rtcTime.Mon),
		int(rtcTime.Mday),
		int(rtcTime.Hour),
		int(rtcTime.Min),
		int(rtcTime.Sec),
		0,
		time.UTC,
	)

	fmt.Println("RTC Time:", goTime)
}
```

**假设的输入与输出:**

* **输入:** 假设 RTC 设备 `/dev/rtc0` 存在且可读。
* **输出:**  程序将打印出 RTC 设备的当前时间，格式类似于 `RTC Time: 2023-10-27 10:30:00 +0000 UTC`。

**代码推理:**

1. 我们首先打开 RTC 设备文件 `/dev/rtc0`，获取其文件描述符。
2. 然后，调用 `unix.IoctlGetRTCTime` 函数，并将文件描述符传递给它。
3. `IoctlGetRTCTime` 内部会调用 `ioctlPtr` 函数，使用 `RTC_RD_TIME` 请求码和指向 `RTCTime` 结构体的指针，执行 `ioctl` 系统调用。
4. 内核会将 RTC 的时间信息填充到 `RTCTime` 结构体中。
5. 我们将 `RTCTime` 结构体中的字段转换为 Go 的 `time.Time` 类型，并进行适当的年份转换。
6. 最后，打印出获取到的时间。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。它主要提供了一组用于执行 `ioctl` 操作的函数。调用这些函数的程序可能会处理命令行参数，以确定要操作的设备、要执行的 `ioctl` 请求以及要传递的数据。

例如，在使用 `ethtool` 的场景中，命令行参数会指定网络接口的名称和要执行的操作（例如，获取驱动信息）。在 Go 代码中，`IoctlGetEthtoolDrvinfo` 函数接收网络接口名称作为参数，并使用它构建 `Ifreq` 结构体，以便传递给 `ioctl` 系统调用。

**使用者易犯错的点:**

1. **错误的文件描述符:**  如果传递给 `Ioctl...` 函数的文件描述符不是对应设备的有效文件描述符，`ioctl` 系统调用将会失败。例如，尝试在没有打开 RTC 设备的情况下调用 `IoctlGetRTCTime`。

    ```go
    // 错误示例：没有打开 RTC 设备
    rtcTime, err := unix.IoctlGetRTCTime(100) // 假设 100 不是有效的 RTC 设备 fd
    if err != nil {
        fmt.Println("Error getting RTC time:", err) // 可能输出 "bad file descriptor" 相关的错误
    }
    ```

2. **错误的 `ioctl` 请求码:** 使用错误的 `req` 参数会导致 `ioctl` 操作执行错误的命令或返回错误的结果。这些请求码通常是与设备驱动程序相关的常量。

3. **不匹配的数据结构:** 传递给 `ioctlPtr` 的数据指针必须指向与 `ioctl` 请求期望的数据结构相匹配的内存。如果结构体的大小或布局不正确，会导致数据损坏或程序崩溃。例如，为 `IoctlSetRTCTime` 传递一个大小不正确的结构体指针。

4. **权限问题:** 某些 `ioctl` 操作可能需要 root 权限才能执行。如果程序没有足够的权限，`ioctl` 系统调用将会失败。例如，尝试在非 root 用户下设置 RTC 时间。

5. **设备特定的错误处理:** 不同的 `ioctl` 操作可能会返回不同的错误码。使用者需要查阅相关的 Linux 内核文档或设备驱动程序文档，以了解特定 `ioctl` 操作可能返回的错误，并进行适当的处理。

总而言之，这段代码提供了一组用于执行底层 `ioctl` 系统调用的 Go 语言接口。使用者需要了解 Linux 系统和相关设备的 `ioctl` 命令和数据结构，才能正确地使用这些函数。错误的使用可能导致程序错误、数据损坏甚至系统不稳定。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/ioctl_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unix

import "unsafe"

// IoctlRetInt performs an ioctl operation specified by req on a device
// associated with opened file descriptor fd, and returns a non-negative
// integer that is returned by the ioctl syscall.
func IoctlRetInt(fd int, req uint) (int, error) {
	ret, _, err := Syscall(SYS_IOCTL, uintptr(fd), uintptr(req), 0)
	if err != 0 {
		return 0, err
	}
	return int(ret), nil
}

func IoctlGetUint32(fd int, req uint) (uint32, error) {
	var value uint32
	err := ioctlPtr(fd, req, unsafe.Pointer(&value))
	return value, err
}

func IoctlGetRTCTime(fd int) (*RTCTime, error) {
	var value RTCTime
	err := ioctlPtr(fd, RTC_RD_TIME, unsafe.Pointer(&value))
	return &value, err
}

func IoctlSetRTCTime(fd int, value *RTCTime) error {
	return ioctlPtr(fd, RTC_SET_TIME, unsafe.Pointer(value))
}

func IoctlGetRTCWkAlrm(fd int) (*RTCWkAlrm, error) {
	var value RTCWkAlrm
	err := ioctlPtr(fd, RTC_WKALM_RD, unsafe.Pointer(&value))
	return &value, err
}

func IoctlSetRTCWkAlrm(fd int, value *RTCWkAlrm) error {
	return ioctlPtr(fd, RTC_WKALM_SET, unsafe.Pointer(value))
}

// IoctlGetEthtoolDrvinfo fetches ethtool driver information for the network
// device specified by ifname.
func IoctlGetEthtoolDrvinfo(fd int, ifname string) (*EthtoolDrvinfo, error) {
	ifr, err := NewIfreq(ifname)
	if err != nil {
		return nil, err
	}

	value := EthtoolDrvinfo{Cmd: ETHTOOL_GDRVINFO}
	ifrd := ifr.withData(unsafe.Pointer(&value))

	err = ioctlIfreqData(fd, SIOCETHTOOL, &ifrd)
	return &value, err
}

// IoctlGetEthtoolTsInfo fetches ethtool timestamping and PHC
// association for the network device specified by ifname.
func IoctlGetEthtoolTsInfo(fd int, ifname string) (*EthtoolTsInfo, error) {
	ifr, err := NewIfreq(ifname)
	if err != nil {
		return nil, err
	}

	value := EthtoolTsInfo{Cmd: ETHTOOL_GET_TS_INFO}
	ifrd := ifr.withData(unsafe.Pointer(&value))

	err = ioctlIfreqData(fd, SIOCETHTOOL, &ifrd)
	return &value, err
}

// IoctlGetHwTstamp retrieves the hardware timestamping configuration
// for the network device specified by ifname.
func IoctlGetHwTstamp(fd int, ifname string) (*HwTstampConfig, error) {
	ifr, err := NewIfreq(ifname)
	if err != nil {
		return nil, err
	}

	value := HwTstampConfig{}
	ifrd := ifr.withData(unsafe.Pointer(&value))

	err = ioctlIfreqData(fd, SIOCGHWTSTAMP, &ifrd)
	return &value, err
}

// IoctlSetHwTstamp updates the hardware timestamping configuration for
// the network device specified by ifname.
func IoctlSetHwTstamp(fd int, ifname string, cfg *HwTstampConfig) error {
	ifr, err := NewIfreq(ifname)
	if err != nil {
		return err
	}
	ifrd := ifr.withData(unsafe.Pointer(cfg))
	return ioctlIfreqData(fd, SIOCSHWTSTAMP, &ifrd)
}

// FdToClockID derives the clock ID from the file descriptor number
// - see clock_gettime(3), FD_TO_CLOCKID macros. The resulting ID is
// suitable for system calls like ClockGettime.
func FdToClockID(fd int) int32 { return int32((int(^fd) << 3) | 3) }

// IoctlPtpClockGetcaps returns the description of a given PTP device.
func IoctlPtpClockGetcaps(fd int) (*PtpClockCaps, error) {
	var value PtpClockCaps
	err := ioctlPtr(fd, PTP_CLOCK_GETCAPS2, unsafe.Pointer(&value))
	return &value, err
}

// IoctlPtpSysOffsetPrecise returns a description of the clock
// offset compared to the system clock.
func IoctlPtpSysOffsetPrecise(fd int) (*PtpSysOffsetPrecise, error) {
	var value PtpSysOffsetPrecise
	err := ioctlPtr(fd, PTP_SYS_OFFSET_PRECISE2, unsafe.Pointer(&value))
	return &value, err
}

// IoctlPtpSysOffsetExtended returns an extended description of the
// clock offset compared to the system clock. The samples parameter
// specifies the desired number of measurements.
func IoctlPtpSysOffsetExtended(fd int, samples uint) (*PtpSysOffsetExtended, error) {
	value := PtpSysOffsetExtended{Samples: uint32(samples)}
	err := ioctlPtr(fd, PTP_SYS_OFFSET_EXTENDED2, unsafe.Pointer(&value))
	return &value, err
}

// IoctlPtpPinGetfunc returns the configuration of the specified
// I/O pin on given PTP device.
func IoctlPtpPinGetfunc(fd int, index uint) (*PtpPinDesc, error) {
	value := PtpPinDesc{Index: uint32(index)}
	err := ioctlPtr(fd, PTP_PIN_GETFUNC2, unsafe.Pointer(&value))
	return &value, err
}

// IoctlPtpPinSetfunc updates configuration of the specified PTP
// I/O pin.
func IoctlPtpPinSetfunc(fd int, pd *PtpPinDesc) error {
	return ioctlPtr(fd, PTP_PIN_SETFUNC2, unsafe.Pointer(pd))
}

// IoctlPtpPeroutRequest configures the periodic output mode of the
// PTP I/O pins.
func IoctlPtpPeroutRequest(fd int, r *PtpPeroutRequest) error {
	return ioctlPtr(fd, PTP_PEROUT_REQUEST2, unsafe.Pointer(r))
}

// IoctlPtpExttsRequest configures the external timestamping mode
// of the PTP I/O pins.
func IoctlPtpExttsRequest(fd int, r *PtpExttsRequest) error {
	return ioctlPtr(fd, PTP_EXTTS_REQUEST2, unsafe.Pointer(r))
}

// IoctlGetWatchdogInfo fetches information about a watchdog device from the
// Linux watchdog API. For more information, see:
// https://www.kernel.org/doc/html/latest/watchdog/watchdog-api.html.
func IoctlGetWatchdogInfo(fd int) (*WatchdogInfo, error) {
	var value WatchdogInfo
	err := ioctlPtr(fd, WDIOC_GETSUPPORT, unsafe.Pointer(&value))
	return &value, err
}

// IoctlWatchdogKeepalive issues a keepalive ioctl to a watchdog device. For
// more information, see:
// https://www.kernel.org/doc/html/latest/watchdog/watchdog-api.html.
func IoctlWatchdogKeepalive(fd int) error {
	// arg is ignored and not a pointer, so ioctl is fine instead of ioctlPtr.
	return ioctl(fd, WDIOC_KEEPALIVE, 0)
}

// IoctlFileCloneRange performs an FICLONERANGE ioctl operation to clone the
// range of data conveyed in value to the file associated with the file
// descriptor destFd. See the ioctl_ficlonerange(2) man page for details.
func IoctlFileCloneRange(destFd int, value *FileCloneRange) error {
	return ioctlPtr(destFd, FICLONERANGE, unsafe.Pointer(value))
}

// IoctlFileClone performs an FICLONE ioctl operation to clone the entire file
// associated with the file description srcFd to the file associated with the
// file descriptor destFd. See the ioctl_ficlone(2) man page for details.
func IoctlFileClone(destFd, srcFd int) error {
	return ioctl(destFd, FICLONE, uintptr(srcFd))
}

type FileDedupeRange struct {
	Src_offset uint64
	Src_length uint64
	Reserved1  uint16
	Reserved2  uint32
	Info       []FileDedupeRangeInfo
}

type FileDedupeRangeInfo struct {
	Dest_fd       int64
	Dest_offset   uint64
	Bytes_deduped uint64
	Status        int32
	Reserved      uint32
}

// IoctlFileDedupeRange performs an FIDEDUPERANGE ioctl operation to share the
// range of data conveyed in value from the file associated with the file
// descriptor srcFd to the value.Info destinations. See the
// ioctl_fideduperange(2) man page for details.
func IoctlFileDedupeRange(srcFd int, value *FileDedupeRange) error {
	buf := make([]byte, SizeofRawFileDedupeRange+
		len(value.Info)*SizeofRawFileDedupeRangeInfo)
	rawrange := (*RawFileDedupeRange)(unsafe.Pointer(&buf[0]))
	rawrange.Src_offset = value.Src_offset
	rawrange.Src_length = value.Src_length
	rawrange.Dest_count = uint16(len(value.Info))
	rawrange.Reserved1 = value.Reserved1
	rawrange.Reserved2 = value.Reserved2

	for i := range value.Info {
		rawinfo := (*RawFileDedupeRangeInfo)(unsafe.Pointer(
			uintptr(unsafe.Pointer(&buf[0])) + uintptr(SizeofRawFileDedupeRange) +
				uintptr(i*SizeofRawFileDedupeRangeInfo)))
		rawinfo.Dest_fd = value.Info[i].Dest_fd
		rawinfo.Dest_offset = value.Info[i].Dest_offset
		rawinfo.Bytes_deduped = value.Info[i].Bytes_deduped
		rawinfo.Status = value.Info[i].Status
		rawinfo.Reserved = value.Info[i].Reserved
	}

	err := ioctlPtr(srcFd, FIDEDUPERANGE, unsafe.Pointer(&buf[0]))

	// Output
	for i := range value.Info {
		rawinfo := (*RawFileDedupeRangeInfo)(unsafe.Pointer(
			uintptr(unsafe.Pointer(&buf[0])) + uintptr(SizeofRawFileDedupeRange) +
				uintptr(i*SizeofRawFileDedupeRangeInfo)))
		value.Info[i].Dest_fd = rawinfo.Dest_fd
		value.Info[i].Dest_offset = rawinfo.Dest_offset
		value.Info[i].Bytes_deduped = rawinfo.Bytes_deduped
		value.Info[i].Status = rawinfo.Status
		value.Info[i].Reserved = rawinfo.Reserved
	}

	return err
}

func IoctlHIDGetDesc(fd int, value *HIDRawReportDescriptor) error {
	return ioctlPtr(fd, HIDIOCGRDESC, unsafe.Pointer(value))
}

func IoctlHIDGetRawInfo(fd int) (*HIDRawDevInfo, error) {
	var value HIDRawDevInfo
	err := ioctlPtr(fd, HIDIOCGRAWINFO, unsafe.Pointer(&value))
	return &value, err
}

func IoctlHIDGetRawName(fd int) (string, error) {
	var value [_HIDIOCGRAWNAME_LEN]byte
	err := ioctlPtr(fd, _HIDIOCGRAWNAME, unsafe.Pointer(&value[0]))
	return ByteSliceToString(value[:]), err
}

func IoctlHIDGetRawPhys(fd int) (string, error) {
	var value [_HIDIOCGRAWPHYS_LEN]byte
	err := ioctlPtr(fd, _HIDIOCGRAWPHYS, unsafe.Pointer(&value[0]))
	return ByteSliceToString(value[:]), err
}

func IoctlHIDGetRawUniq(fd int) (string, error) {
	var value [_HIDIOCGRAWUNIQ_LEN]byte
	err := ioctlPtr(fd, _HIDIOCGRAWUNIQ, unsafe.Pointer(&value[0]))
	return ByteSliceToString(value[:]), err
}

// IoctlIfreq performs an ioctl using an Ifreq structure for input and/or
// output. See the netdevice(7) man page for details.
func IoctlIfreq(fd int, req uint, value *Ifreq) error {
	// It is possible we will add more fields to *Ifreq itself later to prevent
	// misuse, so pass the raw *ifreq directly.
	return ioctlPtr(fd, req, unsafe.Pointer(&value.raw))
}

// TODO(mdlayher): export if and when IfreqData is exported.

// ioctlIfreqData performs an ioctl using an ifreqData structure for input
// and/or output. See the netdevice(7) man page for details.
func ioctlIfreqData(fd int, req uint, value *ifreqData) error {
	// The memory layout of IfreqData (type-safe) and ifreq (not type-safe) are
	// identical so pass *IfreqData directly.
	return ioctlPtr(fd, req, unsafe.Pointer(value))
}

// IoctlKCMClone attaches a new file descriptor to a multiplexor by cloning an
// existing KCM socket, returning a structure containing the file descriptor of
// the new socket.
func IoctlKCMClone(fd int) (*KCMClone, error) {
	var info KCMClone
	if err := ioctlPtr(fd, SIOCKCMCLONE, unsafe.Pointer(&info)); err != nil {
		return nil, err
	}

	return &info, nil
}

// IoctlKCMAttach attaches a TCP socket and associated BPF program file
// descriptor to a multiplexor.
func IoctlKCMAttach(fd int, info KCMAttach) error {
	return ioctlPtr(fd, SIOCKCMATTACH, unsafe.Pointer(&info))
}

// IoctlKCMUnattach unattaches a TCP socket file descriptor from a multiplexor.
func IoctlKCMUnattach(fd int, info KCMUnattach) error {
	return ioctlPtr(fd, SIOCKCMUNATTACH, unsafe.Pointer(&info))
}

// IoctlLoopGetStatus64 gets the status of the loop device associated with the
// file descriptor fd using the LOOP_GET_STATUS64 operation.
func IoctlLoopGetStatus64(fd int) (*LoopInfo64, error) {
	var value LoopInfo64
	if err := ioctlPtr(fd, LOOP_GET_STATUS64, unsafe.Pointer(&value)); err != nil {
		return nil, err
	}
	return &value, nil
}

// IoctlLoopSetStatus64 sets the status of the loop device associated with the
// file descriptor fd using the LOOP_SET_STATUS64 operation.
func IoctlLoopSetStatus64(fd int, value *LoopInfo64) error {
	return ioctlPtr(fd, LOOP_SET_STATUS64, unsafe.Pointer(value))
}

// IoctlLoopConfigure configures all loop device parameters in a single step
func IoctlLoopConfigure(fd int, value *LoopConfig) error {
	return ioctlPtr(fd, LOOP_CONFIGURE, unsafe.Pointer(value))
}

"""



```