Response:
The user wants a summary of the functionalities provided by the Go code snippet in `go/src/net/netip/netip.go`.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Type:** The code defines a central type `Addr`. The package documentation even highlights it. This should be the primary focus.

2. **Analyze `Addr`'s Purpose:** The comments indicate `Addr` represents an IPv4 or IPv6 address, similar to `net.IP` and `net.IPAddr`, but with advantages like being a value type, immutable, and comparable. Note the distinction from `net.IP`.

3. **Examine `Addr`'s Structure:**  It has two main fields: `addr` (a `uint128` for the IP address bits) and `z` (a `unique.Handle[addrDetail]` for address family and zone information). This storage mechanism is a key functional aspect.

4. **Identify Related Types:** The code also defines `AddrPort` (IP address and port) and `Prefix` (IP address and prefix length). These extend the basic IP address functionality.

5. **Categorize Functions Based on the Types:** Go through the functions and associate them with the types they operate on (primarily `Addr`).

    * **Creation/Parsing:** Functions like `AddrFrom4`, `AddrFrom16`, `ParseAddr`, `MustParseAddr`, `AddrFromSlice`. These are essential for getting `Addr` values.
    * **Constants:**  Predefined `Addr` values like `IPv6LinkLocalAllNodes`, `IPv4Unspecified`, etc.
    * **Getters:** Functions like `Zone`, `BitLen`.
    * **Comparisons:** `Compare`, `Less`.
    * **Type Checking:** `Is4`, `Is6`, `Is4In6`.
    * **Manipulation/Conversion:** `Unmap`, `WithZone`, `Prefix`, `As4`, `As16`, `AsSlice`.
    * **Iteration:** `Next`, `Prev`.
    * **String Representation:** `String`, `StringExpanded`, `AppendTo`.
    * **Serialization/Deserialization:** `MarshalText`, `UnmarshalText`, `MarshalBinary`, `UnmarshalBinary`, `AppendBinary`.
    * **Related to `AddrPort`:** `AddrPortFrom`, `ParseAddrPort`, `MustParseAddrPort`.

6. **Group Functionalities Logically:**  Organize the identified functions into meaningful groups like "创建和解析", "信息查询", "类型判断", "转换和操作", "与其他类型比较", "字符串表示", "序列化与反序列化", and "AddrPort 相关". This makes the summary easier to understand.

7. **Summarize the Purpose of Each Group:**  Provide a brief explanation of what each group of functions does.

8. **Highlight Key Features:** Emphasize the advantages of `netip.Addr` over `net.IP` (memory efficiency, immutability, comparability).

9. **Review and Refine:** Read through the summary to ensure clarity, accuracy, and completeness. Make sure the language is clear and concise. For instance, explicitly mentioning that the zero `Addr` is invalid is important.

10. **Address the "Part 1" Instruction:**  Explicitly state that this is a summary of the functionalities in the provided code snippet (Part 1).
这段 Go 语言代码定义了一个名为 `netip` 的包，专注于提供一种更轻量、更高效的 IP 地址表示方式，并在此基础上构建了包含端口和网络前缀的类型。

**主要功能归纳：**

这段代码主要定义并实现了以下核心功能：

1. **`Addr` 类型：**  定义了一个新的 `Addr` 类型，用于表示 IPv4 或 IPv6 地址。与标准库的 `net.IP` 和 `net.IPAddr` 类型相比，`Addr` 类型：
    * **内存占用更小：**  它是一个值类型，直接存储 IP 地址数据，避免了 `net.IP` 使用切片带来的额外开销。
    * **不可变：** `Addr` 的值一旦创建就不能被修改。
    * **可比较：**  可以直接使用 `==` 进行比较，并且可以作为 map 的键。
    * **区分零值：** 零值的 `Addr`（`Addr{}`) 不是一个有效的 IP 地址，与 `0.0.0.0` 和 `::` 不同。

2. **IP 地址的创建和解析：**
    * 提供了多种函数用于创建 `Addr` 类型的实例：
        * `AddrFrom4([4]byte)`: 从 IPv4 的 4 字节数组创建。
        * `AddrFrom16([16]byte)`: 从 IPv6 的 16 字节数组创建。
        * `ParseAddr(string)`:  解析字符串形式的 IP 地址（支持 IPv4、IPv6 和带 Zone 的 IPv6）。
        * `MustParseAddr(string)`:  类似 `ParseAddr`，但在解析失败时会 panic。
        * `AddrFromSlice([]byte)`: 从字节切片创建，支持 4 字节 (IPv4) 和 16 字节 (IPv6)。
    * 定义了 `parseAddrError` 类型用于表示 IP 地址解析错误。
    * 实现了 `parseIPv4` 和 `parseIPv6` 函数用于具体的 IPv4 和 IPv6 地址解析逻辑。

3. **预定义的 IP 地址常量：** 提供了一些常用的 IP 地址常量，例如：
    * `IPv6LinkLocalAllNodes()`
    * `IPv6LinkLocalAllRouters()`
    * `IPv6Loopback()`
    * `IPv6Unspecified()`
    * `IPv4Unspecified()`

4. **IP 地址的信息查询：** 提供了多种方法来查询 `Addr` 实例的信息：
    * `isZero()`: 判断是否为零值。
    * `IsValid()`: 判断是否为有效的 IP 地址（非零值）。
    * `BitLen()`: 获取 IP 地址的位数（IPv4 为 32，IPv6 为 128）。
    * `Zone()`: 获取 IPv6 地址的 Zone 信息。

5. **IP 地址的比较和排序：**
    * `Compare(Addr)`: 比较两个 IP 地址的大小。
    * `Less(Addr)`: 判断一个 IP 地址是否小于另一个。

6. **IP 地址类型判断：**
    * `Is4()`: 判断是否为 IPv4 地址。
    * `Is4In6()`: 判断是否为 IPv4-mapped IPv6 地址。
    * `Is6()`: 判断是否为 IPv6 地址（包括 IPv4-mapped IPv6）。

7. **IP 地址的转换和操作：**
    * `Unmap()`: 如果是 IPv4-mapped IPv6 地址，则转换为 IPv4 地址。
    * `WithZone(string)`: 为 IPv6 地址设置或移除 Zone 信息。
    * `Prefix(int)`:  根据指定的位数截取 IP 地址的前缀。
    * `As16()`: 将 IP 地址转换为 16 字节数组（IPv4 会被映射为 IPv6）。
    * `As4()`: 将 IP 地址转换为 4 字节数组（仅适用于 IPv4 或 IPv4-in-IPv6）。
    * `AsSlice()`: 将 IP 地址转换为字节切片（4 字节或 16 字节）。
    * `Next()`: 获取下一个 IP 地址。
    * `Prev()`: 获取上一个 IP 地址。

8. **IP 地址的字符串表示：**
    * `String()`: 返回 IP 地址的字符串表示形式（IPv4 为点分十进制，IPv6 为标准格式，带 Zone）。
    * `StringExpanded()`: 返回 IPv6 地址的完整展开形式，不进行压缩。
    * `AppendTo([]byte)`: 将 IP 地址的字符串表示追加到字节切片中。

9. **IP 地址的序列化和反序列化：**
    * 实现了 `encoding.TextMarshaler` 和 `encoding.TextUnmarshaler` 接口，可以使用 `MarshalText()` 和 `UnmarshalText()` 方法进行文本序列化和反序列化。
    * 实现了 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口，可以使用 `MarshalBinary()` 和 `UnmarshalBinary()` 方法进行二进制序列化和反序列化。

10. **IP 地址的属性判断：**
    * `IsLinkLocalUnicast()`: 判断是否为链路本地单播地址。
    * `IsLoopback()`: 判断是否为环回地址。
    * `IsMulticast()`: 判断是否为组播地址。
    * `IsInterfaceLocalMulticast()`: 判断是否为接口本地组播地址（仅限 IPv6）。
    * `IsLinkLocalMulticast()`: 判断是否为链路本地组播地址。
    * `IsGlobalUnicast()`: 判断是否为全局单播地址。
    * `IsPrivate()`: 判断是否为私有地址。
    * `IsUnspecified()`: 判断是否为未指定地址（`0.0.0.0` 或 `::`）。

11. **`AddrPort` 类型：** 定义了一个 `AddrPort` 类型，用于表示 IP 地址和端口号的组合。提供了：
    * `AddrPortFrom(Addr, uint16)`: 创建 `AddrPort` 实例。
    * `Addr()`: 获取 `AddrPort` 的 IP 地址。
    * `Port()`: 获取 `AddrPort` 的端口号。
    * `ParseAddrPort(string)`: 解析字符串形式的 IP 地址和端口号。
    * `MustParseAddrPort(string)`: 类似 `ParseAddrPort`，但在解析失败时会 panic。
    * `IsValid()`: 判断 `AddrPort` 的 IP 地址是否有效。
    * `Compare(AddrPort)`: 比较两个 `AddrPort` 的大小。

**总结来说，这段代码的核心在于提供了一个更优的 IP 地址表示类型 `Addr`，以及围绕这个类型提供了一系列创建、解析、查询、比较、转换、序列化和属性判断等功能，同时还定义了包含端口信息的 `AddrPort` 类型。**

### 提示词
```
这是路径为go/src/net/netip/netip.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netip defines an IP address type that's a small value type.
// Building on that [Addr] type, the package also defines [AddrPort] (an
// IP address and a port) and [Prefix] (an IP address and a bit length
// prefix).
//
// Compared to the [net.IP] type, [Addr] type takes less memory, is immutable,
// and is comparable (supports == and being a map key).
package netip

import (
	"cmp"
	"errors"
	"internal/bytealg"
	"internal/byteorder"
	"internal/itoa"
	"math"
	"strconv"
	"unique"
)

// Sizes: (64-bit)
//   net.IP:     24 byte slice header + {4, 16} = 28 to 40 bytes
//   net.IPAddr: 40 byte slice header + {4, 16} = 44 to 56 bytes + zone length
//   netip.Addr: 24 bytes (zone is per-name singleton, shared across all users)

// Addr represents an IPv4 or IPv6 address (with or without a scoped
// addressing zone), similar to [net.IP] or [net.IPAddr].
//
// Unlike [net.IP] or [net.IPAddr], Addr is a comparable value
// type (it supports == and can be a map key) and is immutable.
//
// The zero Addr is not a valid IP address.
// Addr{} is distinct from both 0.0.0.0 and ::.
type Addr struct {
	// addr is the hi and lo bits of an IPv6 address. If z==z4,
	// hi and lo contain the IPv4-mapped IPv6 address.
	//
	// hi and lo are constructed by interpreting a 16-byte IPv6
	// address as a big-endian 128-bit number. The most significant
	// bits of that number go into hi, the rest into lo.
	//
	// For example, 0011:2233:4455:6677:8899:aabb:ccdd:eeff is stored as:
	//  addr.hi = 0x0011223344556677
	//  addr.lo = 0x8899aabbccddeeff
	//
	// We store IPs like this, rather than as [16]byte, because it
	// turns most operations on IPs into arithmetic and bit-twiddling
	// operations on 64-bit registers, which is much faster than
	// bytewise processing.
	addr uint128

	// Details about the address, wrapped up together and canonicalized.
	z unique.Handle[addrDetail]
}

// addrDetail represents the details of an Addr, like address family and IPv6 zone.
type addrDetail struct {
	isV6   bool   // IPv4 is false, IPv6 is true.
	zoneV6 string // != "" only if IsV6 is true.
}

// z0, z4, and z6noz are sentinel Addr.z values.
// See the Addr type's field docs.
var (
	z0    unique.Handle[addrDetail]
	z4    = unique.Make(addrDetail{})
	z6noz = unique.Make(addrDetail{isV6: true})
)

// IPv6LinkLocalAllNodes returns the IPv6 link-local all nodes multicast
// address ff02::1.
func IPv6LinkLocalAllNodes() Addr { return AddrFrom16([16]byte{0: 0xff, 1: 0x02, 15: 0x01}) }

// IPv6LinkLocalAllRouters returns the IPv6 link-local all routers multicast
// address ff02::2.
func IPv6LinkLocalAllRouters() Addr { return AddrFrom16([16]byte{0: 0xff, 1: 0x02, 15: 0x02}) }

// IPv6Loopback returns the IPv6 loopback address ::1.
func IPv6Loopback() Addr { return AddrFrom16([16]byte{15: 0x01}) }

// IPv6Unspecified returns the IPv6 unspecified address "::".
func IPv6Unspecified() Addr { return Addr{z: z6noz} }

// IPv4Unspecified returns the IPv4 unspecified address "0.0.0.0".
func IPv4Unspecified() Addr { return AddrFrom4([4]byte{}) }

// AddrFrom4 returns the address of the IPv4 address given by the bytes in addr.
func AddrFrom4(addr [4]byte) Addr {
	return Addr{
		addr: uint128{0, 0xffff00000000 | uint64(addr[0])<<24 | uint64(addr[1])<<16 | uint64(addr[2])<<8 | uint64(addr[3])},
		z:    z4,
	}
}

// AddrFrom16 returns the IPv6 address given by the bytes in addr.
// An IPv4-mapped IPv6 address is left as an IPv6 address.
// (Use Unmap to convert them if needed.)
func AddrFrom16(addr [16]byte) Addr {
	return Addr{
		addr: uint128{
			byteorder.BEUint64(addr[:8]),
			byteorder.BEUint64(addr[8:]),
		},
		z: z6noz,
	}
}

// ParseAddr parses s as an IP address, returning the result. The string
// s can be in dotted decimal ("192.0.2.1"), IPv6 ("2001:db8::68"),
// or IPv6 with a scoped addressing zone ("fe80::1cc0:3e8c:119f:c2e1%ens18").
func ParseAddr(s string) (Addr, error) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return parseIPv4(s)
		case ':':
			return parseIPv6(s)
		case '%':
			// Assume that this was trying to be an IPv6 address with
			// a zone specifier, but the address is missing.
			return Addr{}, parseAddrError{in: s, msg: "missing IPv6 address"}
		}
	}
	return Addr{}, parseAddrError{in: s, msg: "unable to parse IP"}
}

// MustParseAddr calls [ParseAddr](s) and panics on error.
// It is intended for use in tests with hard-coded strings.
func MustParseAddr(s string) Addr {
	ip, err := ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return ip
}

type parseAddrError struct {
	in  string // the string given to ParseAddr
	msg string // an explanation of the parse failure
	at  string // optionally, the unparsed portion of in at which the error occurred.
}

func (err parseAddrError) Error() string {
	q := strconv.Quote
	if err.at != "" {
		return "ParseAddr(" + q(err.in) + "): " + err.msg + " (at " + q(err.at) + ")"
	}
	return "ParseAddr(" + q(err.in) + "): " + err.msg
}

func parseIPv4Fields(in string, off, end int, fields []uint8) error {
	var val, pos int
	var digLen int // number of digits in current octet
	s := in[off:end]
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if digLen == 1 && val == 0 {
				return parseAddrError{in: in, msg: "IPv4 field has octet with leading zero"}
			}
			val = val*10 + int(s[i]) - '0'
			digLen++
			if val > 255 {
				return parseAddrError{in: in, msg: "IPv4 field has value >255"}
			}
		} else if s[i] == '.' {
			// .1.2.3
			// 1.2.3.
			// 1..2.3
			if i == 0 || i == len(s)-1 || s[i-1] == '.' {
				return parseAddrError{in: in, msg: "IPv4 field must have at least one digit", at: s[i:]}
			}
			// 1.2.3.4.5
			if pos == 3 {
				return parseAddrError{in: in, msg: "IPv4 address too long"}
			}
			fields[pos] = uint8(val)
			pos++
			val = 0
			digLen = 0
		} else {
			return parseAddrError{in: in, msg: "unexpected character", at: s[i:]}
		}
	}
	if pos < 3 {
		return parseAddrError{in: in, msg: "IPv4 address too short"}
	}
	fields[3] = uint8(val)
	return nil
}

// parseIPv4 parses s as an IPv4 address (in form "192.168.0.1").
func parseIPv4(s string) (ip Addr, err error) {
	var fields [4]uint8
	err = parseIPv4Fields(s, 0, len(s), fields[:])
	if err != nil {
		return Addr{}, err
	}
	return AddrFrom4(fields), nil
}

// parseIPv6 parses s as an IPv6 address (in form "2001:db8::68").
func parseIPv6(in string) (Addr, error) {
	s := in

	// Split off the zone right from the start. Yes it's a second scan
	// of the string, but trying to handle it inline makes a bunch of
	// other inner loop conditionals more expensive, and it ends up
	// being slower.
	zone := ""
	i := bytealg.IndexByteString(s, '%')
	if i != -1 {
		s, zone = s[:i], s[i+1:]
		if zone == "" {
			// Not allowed to have an empty zone if explicitly specified.
			return Addr{}, parseAddrError{in: in, msg: "zone must be a non-empty string"}
		}
	}

	var ip [16]byte
	ellipsis := -1 // position of ellipsis in ip

	// Might have leading ellipsis
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		// Might be only ellipsis
		if len(s) == 0 {
			return IPv6Unspecified().WithZone(zone), nil
		}
	}

	// Loop, parsing hex numbers followed by colon.
	i = 0
	for i < 16 {
		// Hex number. Similar to parseIPv4, inlining the hex number
		// parsing yields a significant performance increase.
		off := 0
		acc := uint32(0)
		for ; off < len(s); off++ {
			c := s[off]
			if c >= '0' && c <= '9' {
				acc = (acc << 4) + uint32(c-'0')
			} else if c >= 'a' && c <= 'f' {
				acc = (acc << 4) + uint32(c-'a'+10)
			} else if c >= 'A' && c <= 'F' {
				acc = (acc << 4) + uint32(c-'A'+10)
			} else {
				break
			}
			if off > 3 {
				//more than 4 digits in group, fail.
				return Addr{}, parseAddrError{in: in, msg: "each group must have 4 or less digits", at: s}
			}
			if acc > math.MaxUint16 {
				// Overflow, fail.
				return Addr{}, parseAddrError{in: in, msg: "IPv6 field has value >=2^16", at: s}
			}
		}
		if off == 0 {
			// No digits found, fail.
			return Addr{}, parseAddrError{in: in, msg: "each colon-separated field must have at least one digit", at: s}
		}

		// If followed by dot, might be in trailing IPv4.
		if off < len(s) && s[off] == '.' {
			if ellipsis < 0 && i != 12 {
				// Not the right place.
				return Addr{}, parseAddrError{in: in, msg: "embedded IPv4 address must replace the final 2 fields of the address", at: s}
			}
			if i+4 > 16 {
				// Not enough room.
				return Addr{}, parseAddrError{in: in, msg: "too many hex fields to fit an embedded IPv4 at the end of the address", at: s}
			}

			end := len(in)
			if len(zone) > 0 {
				end -= len(zone) + 1
			}
			err := parseIPv4Fields(in, end-len(s), end, ip[i:i+4])
			if err != nil {
				return Addr{}, err
			}
			s = ""
			i += 4
			break
		}

		// Save this 16-bit chunk.
		ip[i] = byte(acc >> 8)
		ip[i+1] = byte(acc)
		i += 2

		// Stop at end of string.
		s = s[off:]
		if len(s) == 0 {
			break
		}

		// Otherwise must be followed by colon and more.
		if s[0] != ':' {
			return Addr{}, parseAddrError{in: in, msg: "unexpected character, want colon", at: s}
		} else if len(s) == 1 {
			return Addr{}, parseAddrError{in: in, msg: "colon must be followed by more characters", at: s}
		}
		s = s[1:]

		// Look for ellipsis.
		if s[0] == ':' {
			if ellipsis >= 0 { // already have one
				return Addr{}, parseAddrError{in: in, msg: "multiple :: in address", at: s}
			}
			ellipsis = i
			s = s[1:]
			if len(s) == 0 { // can be at end
				break
			}
		}
	}

	// Must have used entire string.
	if len(s) != 0 {
		return Addr{}, parseAddrError{in: in, msg: "trailing garbage after address", at: s}
	}

	// If didn't parse enough, expand ellipsis.
	if i < 16 {
		if ellipsis < 0 {
			return Addr{}, parseAddrError{in: in, msg: "address string too short"}
		}
		n := 16 - i
		for j := i - 1; j >= ellipsis; j-- {
			ip[j+n] = ip[j]
		}
		clear(ip[ellipsis : ellipsis+n])
	} else if ellipsis >= 0 {
		// Ellipsis must represent at least one 0 group.
		return Addr{}, parseAddrError{in: in, msg: "the :: must expand to at least one field of zeros"}
	}
	return AddrFrom16(ip).WithZone(zone), nil
}

// AddrFromSlice parses the 4- or 16-byte byte slice as an IPv4 or IPv6 address.
// Note that a [net.IP] can be passed directly as the []byte argument.
// If slice's length is not 4 or 16, AddrFromSlice returns [Addr]{}, false.
func AddrFromSlice(slice []byte) (ip Addr, ok bool) {
	switch len(slice) {
	case 4:
		return AddrFrom4([4]byte(slice)), true
	case 16:
		return AddrFrom16([16]byte(slice)), true
	}
	return Addr{}, false
}

// v4 returns the i'th byte of ip. If ip is not an IPv4, v4 returns
// unspecified garbage.
func (ip Addr) v4(i uint8) uint8 {
	return uint8(ip.addr.lo >> ((3 - i) * 8))
}

// v6 returns the i'th byte of ip. If ip is an IPv4 address, this
// accesses the IPv4-mapped IPv6 address form of the IP.
func (ip Addr) v6(i uint8) uint8 {
	return uint8(*(ip.addr.halves()[(i/8)%2]) >> ((7 - i%8) * 8))
}

// v6u16 returns the i'th 16-bit word of ip. If ip is an IPv4 address,
// this accesses the IPv4-mapped IPv6 address form of the IP.
func (ip Addr) v6u16(i uint8) uint16 {
	return uint16(*(ip.addr.halves()[(i/4)%2]) >> ((3 - i%4) * 16))
}

// isZero reports whether ip is the zero value of the IP type.
// The zero value is not a valid IP address of any type.
//
// Note that "0.0.0.0" and "::" are not the zero value. Use IsUnspecified to
// check for these values instead.
func (ip Addr) isZero() bool {
	// Faster than comparing ip == Addr{}, but effectively equivalent,
	// as there's no way to make an IP with a nil z from this package.
	return ip.z == z0
}

// IsValid reports whether the [Addr] is an initialized address (not the zero Addr).
//
// Note that "0.0.0.0" and "::" are both valid values.
func (ip Addr) IsValid() bool { return ip.z != z0 }

// BitLen returns the number of bits in the IP address:
// 128 for IPv6, 32 for IPv4, and 0 for the zero [Addr].
//
// Note that IPv4-mapped IPv6 addresses are considered IPv6 addresses
// and therefore have bit length 128.
func (ip Addr) BitLen() int {
	switch ip.z {
	case z0:
		return 0
	case z4:
		return 32
	}
	return 128
}

// Zone returns ip's IPv6 scoped addressing zone, if any.
func (ip Addr) Zone() string {
	if ip.z == z0 {
		return ""
	}
	return ip.z.Value().zoneV6
}

// Compare returns an integer comparing two IPs.
// The result will be 0 if ip == ip2, -1 if ip < ip2, and +1 if ip > ip2.
// The definition of "less than" is the same as the [Addr.Less] method.
func (ip Addr) Compare(ip2 Addr) int {
	f1, f2 := ip.BitLen(), ip2.BitLen()
	if f1 < f2 {
		return -1
	}
	if f1 > f2 {
		return 1
	}
	hi1, hi2 := ip.addr.hi, ip2.addr.hi
	if hi1 < hi2 {
		return -1
	}
	if hi1 > hi2 {
		return 1
	}
	lo1, lo2 := ip.addr.lo, ip2.addr.lo
	if lo1 < lo2 {
		return -1
	}
	if lo1 > lo2 {
		return 1
	}
	if ip.Is6() {
		za, zb := ip.Zone(), ip2.Zone()
		if za < zb {
			return -1
		}
		if za > zb {
			return 1
		}
	}
	return 0
}

// Less reports whether ip sorts before ip2.
// IP addresses sort first by length, then their address.
// IPv6 addresses with zones sort just after the same address without a zone.
func (ip Addr) Less(ip2 Addr) bool { return ip.Compare(ip2) == -1 }

// Is4 reports whether ip is an IPv4 address.
//
// It returns false for IPv4-mapped IPv6 addresses. See [Addr.Unmap].
func (ip Addr) Is4() bool {
	return ip.z == z4
}

// Is4In6 reports whether ip is an "IPv4-mapped IPv6 address"
// as defined by RFC 4291.
// That is, it reports whether ip is in ::ffff:0:0/96.
func (ip Addr) Is4In6() bool {
	return ip.Is6() && ip.addr.hi == 0 && ip.addr.lo>>32 == 0xffff
}

// Is6 reports whether ip is an IPv6 address, including IPv4-mapped
// IPv6 addresses.
func (ip Addr) Is6() bool {
	return ip.z != z0 && ip.z != z4
}

// Unmap returns ip with any IPv4-mapped IPv6 address prefix removed.
//
// That is, if ip is an IPv6 address wrapping an IPv4 address, it
// returns the wrapped IPv4 address. Otherwise it returns ip unmodified.
func (ip Addr) Unmap() Addr {
	if ip.Is4In6() {
		ip.z = z4
	}
	return ip
}

// WithZone returns an IP that's the same as ip but with the provided
// zone. If zone is empty, the zone is removed. If ip is an IPv4
// address, WithZone is a no-op and returns ip unchanged.
func (ip Addr) WithZone(zone string) Addr {
	if !ip.Is6() {
		return ip
	}
	if zone == "" {
		ip.z = z6noz
		return ip
	}
	ip.z = unique.Make(addrDetail{isV6: true, zoneV6: zone})
	return ip
}

// withoutZone unconditionally strips the zone from ip.
// It's similar to WithZone, but small enough to be inlinable.
func (ip Addr) withoutZone() Addr {
	if !ip.Is6() {
		return ip
	}
	ip.z = z6noz
	return ip
}

// hasZone reports whether ip has an IPv6 zone.
func (ip Addr) hasZone() bool {
	return ip.z != z0 && ip.z != z4 && ip.z != z6noz
}

// IsLinkLocalUnicast reports whether ip is a link-local unicast address.
func (ip Addr) IsLinkLocalUnicast() bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	// Dynamic Configuration of IPv4 Link-Local Addresses
	// https://datatracker.ietf.org/doc/html/rfc3927#section-2.1
	if ip.Is4() {
		return ip.v4(0) == 169 && ip.v4(1) == 254
	}
	// IP Version 6 Addressing Architecture (2.4 Address Type Identification)
	// https://datatracker.ietf.org/doc/html/rfc4291#section-2.4
	if ip.Is6() {
		return ip.v6u16(0)&0xffc0 == 0xfe80
	}
	return false // zero value
}

// IsLoopback reports whether ip is a loopback address.
func (ip Addr) IsLoopback() bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	// Requirements for Internet Hosts -- Communication Layers (3.2.1.3 Addressing)
	// https://datatracker.ietf.org/doc/html/rfc1122#section-3.2.1.3
	if ip.Is4() {
		return ip.v4(0) == 127
	}
	// IP Version 6 Addressing Architecture (2.4 Address Type Identification)
	// https://datatracker.ietf.org/doc/html/rfc4291#section-2.4
	if ip.Is6() {
		return ip.addr.hi == 0 && ip.addr.lo == 1
	}
	return false // zero value
}

// IsMulticast reports whether ip is a multicast address.
func (ip Addr) IsMulticast() bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	// Host Extensions for IP Multicasting (4. HOST GROUP ADDRESSES)
	// https://datatracker.ietf.org/doc/html/rfc1112#section-4
	if ip.Is4() {
		return ip.v4(0)&0xf0 == 0xe0
	}
	// IP Version 6 Addressing Architecture (2.4 Address Type Identification)
	// https://datatracker.ietf.org/doc/html/rfc4291#section-2.4
	if ip.Is6() {
		return ip.addr.hi>>(64-8) == 0xff // ip.v6(0) == 0xff
	}
	return false // zero value
}

// IsInterfaceLocalMulticast reports whether ip is an IPv6 interface-local
// multicast address.
func (ip Addr) IsInterfaceLocalMulticast() bool {
	// IPv6 Addressing Architecture (2.7.1. Pre-Defined Multicast Addresses)
	// https://datatracker.ietf.org/doc/html/rfc4291#section-2.7.1
	if ip.Is6() && !ip.Is4In6() {
		return ip.v6u16(0)&0xff0f == 0xff01
	}
	return false // zero value
}

// IsLinkLocalMulticast reports whether ip is a link-local multicast address.
func (ip Addr) IsLinkLocalMulticast() bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	// IPv4 Multicast Guidelines (4. Local Network Control Block (224.0.0/24))
	// https://datatracker.ietf.org/doc/html/rfc5771#section-4
	if ip.Is4() {
		return ip.v4(0) == 224 && ip.v4(1) == 0 && ip.v4(2) == 0
	}
	// IPv6 Addressing Architecture (2.7.1. Pre-Defined Multicast Addresses)
	// https://datatracker.ietf.org/doc/html/rfc4291#section-2.7.1
	if ip.Is6() {
		return ip.v6u16(0)&0xff0f == 0xff02
	}
	return false // zero value
}

// IsGlobalUnicast reports whether ip is a global unicast address.
//
// It returns true for IPv6 addresses which fall outside of the current
// IANA-allocated 2000::/3 global unicast space, with the exception of the
// link-local address space. It also returns true even if ip is in the IPv4
// private address space or IPv6 unique local address space.
// It returns false for the zero [Addr].
//
// For reference, see RFC 1122, RFC 4291, and RFC 4632.
func (ip Addr) IsGlobalUnicast() bool {
	if ip.z == z0 {
		// Invalid or zero-value.
		return false
	}

	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	// Match package net's IsGlobalUnicast logic. Notably private IPv4 addresses
	// and ULA IPv6 addresses are still considered "global unicast".
	if ip.Is4() && (ip == IPv4Unspecified() || ip == AddrFrom4([4]byte{255, 255, 255, 255})) {
		return false
	}

	return ip != IPv6Unspecified() &&
		!ip.IsLoopback() &&
		!ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast()
}

// IsPrivate reports whether ip is a private address, according to RFC 1918
// (IPv4 addresses) and RFC 4193 (IPv6 addresses). That is, it reports whether
// ip is in 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or fc00::/7. This is the
// same as [net.IP.IsPrivate].
func (ip Addr) IsPrivate() bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}

	// Match the stdlib's IsPrivate logic.
	if ip.Is4() {
		// RFC 1918 allocates 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 as
		// private IPv4 address subnets.
		return ip.v4(0) == 10 ||
			(ip.v4(0) == 172 && ip.v4(1)&0xf0 == 16) ||
			(ip.v4(0) == 192 && ip.v4(1) == 168)
	}

	if ip.Is6() {
		// RFC 4193 allocates fc00::/7 as the unique local unicast IPv6 address
		// subnet.
		return ip.v6(0)&0xfe == 0xfc
	}

	return false // zero value
}

// IsUnspecified reports whether ip is an unspecified address, either the IPv4
// address "0.0.0.0" or the IPv6 address "::".
//
// Note that the zero [Addr] is not an unspecified address.
func (ip Addr) IsUnspecified() bool {
	return ip == IPv4Unspecified() || ip == IPv6Unspecified()
}

// Prefix keeps only the top b bits of IP, producing a Prefix
// of the specified length.
// If ip is a zero [Addr], Prefix always returns a zero Prefix and a nil error.
// Otherwise, if bits is less than zero or greater than ip.BitLen(),
// Prefix returns an error.
func (ip Addr) Prefix(b int) (Prefix, error) {
	if b < 0 {
		return Prefix{}, errors.New("negative Prefix bits")
	}
	effectiveBits := b
	switch ip.z {
	case z0:
		return Prefix{}, nil
	case z4:
		if b > 32 {
			return Prefix{}, errors.New("prefix length " + itoa.Itoa(b) + " too large for IPv4")
		}
		effectiveBits += 96
	default:
		if b > 128 {
			return Prefix{}, errors.New("prefix length " + itoa.Itoa(b) + " too large for IPv6")
		}
	}
	ip.addr = ip.addr.and(mask6(effectiveBits))
	return PrefixFrom(ip, b), nil
}

// As16 returns the IP address in its 16-byte representation.
// IPv4 addresses are returned as IPv4-mapped IPv6 addresses.
// IPv6 addresses with zones are returned without their zone (use the
// [Addr.Zone] method to get it).
// The ip zero value returns all zeroes.
func (ip Addr) As16() (a16 [16]byte) {
	byteorder.BEPutUint64(a16[:8], ip.addr.hi)
	byteorder.BEPutUint64(a16[8:], ip.addr.lo)
	return a16
}

// As4 returns an IPv4 or IPv4-in-IPv6 address in its 4-byte representation.
// If ip is the zero [Addr] or an IPv6 address, As4 panics.
// Note that 0.0.0.0 is not the zero Addr.
func (ip Addr) As4() (a4 [4]byte) {
	if ip.z == z4 || ip.Is4In6() {
		byteorder.BEPutUint32(a4[:], uint32(ip.addr.lo))
		return a4
	}
	if ip.z == z0 {
		panic("As4 called on IP zero value")
	}
	panic("As4 called on IPv6 address")
}

// AsSlice returns an IPv4 or IPv6 address in its respective 4-byte or 16-byte representation.
func (ip Addr) AsSlice() []byte {
	switch ip.z {
	case z0:
		return nil
	case z4:
		var ret [4]byte
		byteorder.BEPutUint32(ret[:], uint32(ip.addr.lo))
		return ret[:]
	default:
		var ret [16]byte
		byteorder.BEPutUint64(ret[:8], ip.addr.hi)
		byteorder.BEPutUint64(ret[8:], ip.addr.lo)
		return ret[:]
	}
}

// Next returns the address following ip.
// If there is none, it returns the zero [Addr].
func (ip Addr) Next() Addr {
	ip.addr = ip.addr.addOne()
	if ip.Is4() {
		if uint32(ip.addr.lo) == 0 {
			// Overflowed.
			return Addr{}
		}
	} else {
		if ip.addr.isZero() {
			// Overflowed
			return Addr{}
		}
	}
	return ip
}

// Prev returns the IP before ip.
// If there is none, it returns the IP zero value.
func (ip Addr) Prev() Addr {
	if ip.Is4() {
		if uint32(ip.addr.lo) == 0 {
			return Addr{}
		}
	} else if ip.addr.isZero() {
		return Addr{}
	}
	ip.addr = ip.addr.subOne()
	return ip
}

// String returns the string form of the IP address ip.
// It returns one of 5 forms:
//
//   - "invalid IP", if ip is the zero [Addr]
//   - IPv4 dotted decimal ("192.0.2.1")
//   - IPv6 ("2001:db8::1")
//   - "::ffff:1.2.3.4" (if [Addr.Is4In6])
//   - IPv6 with zone ("fe80:db8::1%eth0")
//
// Note that unlike package net's IP.String method,
// IPv4-mapped IPv6 addresses format with a "::ffff:"
// prefix before the dotted quad.
func (ip Addr) String() string {
	switch ip.z {
	case z0:
		return "invalid IP"
	case z4:
		return ip.string4()
	default:
		if ip.Is4In6() {
			return ip.string4In6()
		}
		return ip.string6()
	}
}

// AppendTo appends a text encoding of ip,
// as generated by [Addr.MarshalText],
// to b and returns the extended buffer.
func (ip Addr) AppendTo(b []byte) []byte {
	switch ip.z {
	case z0:
		return b
	case z4:
		return ip.appendTo4(b)
	default:
		if ip.Is4In6() {
			return ip.appendTo4In6(b)
		}
		return ip.appendTo6(b)
	}
}

// digits is a string of the hex digits from 0 to f. It's used in
// appendDecimal and appendHex to format IP addresses.
const digits = "0123456789abcdef"

// appendDecimal appends the decimal string representation of x to b.
func appendDecimal(b []byte, x uint8) []byte {
	// Using this function rather than strconv.AppendUint makes IPv4
	// string building 2x faster.

	if x >= 100 {
		b = append(b, digits[x/100])
	}
	if x >= 10 {
		b = append(b, digits[x/10%10])
	}
	return append(b, digits[x%10])
}

// appendHex appends the hex string representation of x to b.
func appendHex(b []byte, x uint16) []byte {
	// Using this function rather than strconv.AppendUint makes IPv6
	// string building 2x faster.

	if x >= 0x1000 {
		b = append(b, digits[x>>12])
	}
	if x >= 0x100 {
		b = append(b, digits[x>>8&0xf])
	}
	if x >= 0x10 {
		b = append(b, digits[x>>4&0xf])
	}
	return append(b, digits[x&0xf])
}

// appendHexPad appends the fully padded hex string representation of x to b.
func appendHexPad(b []byte, x uint16) []byte {
	return append(b, digits[x>>12], digits[x>>8&0xf], digits[x>>4&0xf], digits[x&0xf])
}

func (ip Addr) string4() string {
	const max = len("255.255.255.255")
	ret := make([]byte, 0, max)
	ret = ip.appendTo4(ret)
	return string(ret)
}

func (ip Addr) appendTo4(ret []byte) []byte {
	ret = appendDecimal(ret, ip.v4(0))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(1))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(2))
	ret = append(ret, '.')
	ret = appendDecimal(ret, ip.v4(3))
	return ret
}

func (ip Addr) string4In6() string {
	const max = len("::ffff:255.255.255.255%enp5s0")
	ret := make([]byte, 0, max)
	ret = ip.appendTo4In6(ret)
	return string(ret)
}

func (ip Addr) appendTo4In6(ret []byte) []byte {
	ret = append(ret, "::ffff:"...)
	ret = ip.Unmap().appendTo4(ret)
	if ip.z != z6noz {
		ret = append(ret, '%')
		ret = append(ret, ip.Zone()...)
	}
	return ret
}

// string6 formats ip in IPv6 textual representation. It follows the
// guidelines in section 4 of RFC 5952
// (https://tools.ietf.org/html/rfc5952#section-4): no unnecessary
// zeros, use :: to elide the longest run of zeros, and don't use ::
// to compact a single zero field.
func (ip Addr) string6() string {
	// Use a zone with a "plausibly long" name, so that most zone-ful
	// IP addresses won't require additional allocation.
	//
	// The compiler does a cool optimization here, where ret ends up
	// stack-allocated and so the only allocation this function does
	// is to construct the returned string. As such, it's okay to be a
	// bit greedy here, size-wise.
	const max = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%enp5s0")
	ret := make([]byte, 0, max)
	ret = ip.appendTo6(ret)
	return string(ret)
}

func (ip Addr) appendTo6(ret []byte) []byte {
	zeroStart, zeroEnd := uint8(255), uint8(255)
	for i := uint8(0); i < 8; i++ {
		j := i
		for j < 8 && ip.v6u16(j) == 0 {
			j++
		}
		if l := j - i; l >= 2 && l > zeroEnd-zeroStart {
			zeroStart, zeroEnd = i, j
		}
	}

	for i := uint8(0); i < 8; i++ {
		if i == zeroStart {
			ret = append(ret, ':', ':')
			i = zeroEnd
			if i >= 8 {
				break
			}
		} else if i > 0 {
			ret = append(ret, ':')
		}

		ret = appendHex(ret, ip.v6u16(i))
	}

	if ip.z != z6noz {
		ret = append(ret, '%')
		ret = append(ret, ip.Zone()...)
	}
	return ret
}

// StringExpanded is like [Addr.String] but IPv6 addresses are expanded with leading
// zeroes and no "::" compression. For example, "2001:db8::1" becomes
// "2001:0db8:0000:0000:0000:0000:0000:0001".
func (ip Addr) StringExpanded() string {
	switch ip.z {
	case z0, z4:
		return ip.String()
	}

	const size = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	ret := make([]byte, 0, size)
	for i := uint8(0); i < 8; i++ {
		if i > 0 {
			ret = append(ret, ':')
		}

		ret = appendHexPad(ret, ip.v6u16(i))
	}

	if ip.z != z6noz {
		// The addition of a zone will cause a second allocation, but when there
		// is no zone the ret slice will be stack allocated.
		ret = append(ret, '%')
		ret = append(ret, ip.Zone()...)
	}
	return string(ret)
}

// AppendText implements the [encoding.TextAppender] interface,
// It is the same as [Addr.AppendTo].
func (ip Addr) AppendText(b []byte) ([]byte, error) {
	return ip.AppendTo(b), nil
}

// MarshalText implements the [encoding.TextMarshaler] interface,
// The encoding is the same as returned by [Addr.String], with one exception:
// If ip is the zero [Addr], the encoding is the empty string.
func (ip Addr) MarshalText() ([]byte, error) {
	buf := []byte{}
	switch ip.z {
	case z0:
	case z4:
		const maxCap = len("255.255.255.255")
		buf = make([]byte, 0, maxCap)
	default:
		if ip.Is4In6() {
			const maxCap = len("::ffff:255.255.255.255%enp5s0")
			buf = make([]byte, 0, maxCap)
			break
		}
		const maxCap = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%enp5s0")
		buf = make([]byte, 0, maxCap)
	}
	return ip.AppendText(buf)
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// The IP address is expected in a form accepted by [ParseAddr].
//
// If text is empty, UnmarshalText sets *ip to the zero [Addr] and
// returns no error.
func (ip *Addr) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*ip = Addr{}
		return nil
	}
	var err error
	*ip, err = ParseAddr(string(text))
	return err
}

// AppendBinary implements the [encoding.BinaryAppender] interface.
func (ip Addr) AppendBinary(b []byte) ([]byte, error) {
	switch ip.z {
	case z0:
	case z4:
		b = byteorder.BEAppendUint32(b, uint32(ip.addr.lo))
	default:
		b = byteorder.BEAppendUint64(b, ip.addr.hi)
		b = byteorder.BEAppendUint64(b, ip.addr.lo)
		b = append(b, ip.Zone()...)
	}
	return b, nil
}

func (ip Addr) marshalBinarySize() int {
	switch ip.z {
	case z0:
		return 0
	case z4:
		return 4
	default:
		return 16 + len(ip.Zone())
	}
}

// MarshalBinary implements the [encoding.BinaryMarshaler] interface.
// It returns a zero-length slice for the zero [Addr],
// the 4-byte form for an IPv4 address,
// and the 16-byte form with zone appended for an IPv6 address.
func (ip Addr) MarshalBinary() ([]byte, error) {
	return ip.AppendBinary(make([]byte, 0, ip.marshalBinarySize()))
}

// UnmarshalBinary implements the [encoding.BinaryUnmarshaler] interface.
// It expects data in the form generated by MarshalBinary.
func (ip *Addr) UnmarshalBinary(b []byte) error {
	n := len(b)
	switch {
	case n == 0:
		*ip = Addr{}
		return nil
	case n == 4:
		*ip = AddrFrom4([4]byte(b))
		return nil
	case n == 16:
		*ip = AddrFrom16([16]byte(b))
		return nil
	case n > 16:
		*ip = AddrFrom16([16]byte(b[:16])).WithZone(string(b[16:]))
		return nil
	}
	return errors.New("unexpected slice size")
}

// AddrPort is an IP and a port number.
type AddrPort struct {
	ip   Addr
	port uint16
}

// AddrPortFrom returns an [AddrPort] with the provided IP and port.
// It does not allocate.
func AddrPortFrom(ip Addr, port uint16) AddrPort { return AddrPort{ip: ip, port: port} }

// Addr returns p's IP address.
func (p AddrPort) Addr() Addr { return p.ip }

// Port returns p's port.
func (p AddrPort) Port() uint16 { return p.port }

// splitAddrPort splits s into an IP address string and a port
// string. It splits strings shaped like "foo:bar" or "[foo]:bar",
// without further validating the substrings. v6 indicates whether the
// ip string should parse as an IPv6 address or an IPv4 address, in
// order for s to be a valid ip:port string.
func splitAddrPort(s string) (ip, port string, v6 bool, err error) {
	i := bytealg.LastIndexByteString(s, ':')
	if i == -1 {
		return "", "", false, errors.New("not an ip:port")
	}

	ip, port = s[:i], s[i+1:]
	if len(ip) == 0 {
		return "", "", false, errors.New("no IP")
	}
	if len(port) == 0 {
		return "", "", false, errors.New("no port")
	}
	if ip[0] == '[' {
		if len(ip) < 2 || ip[len(ip)-1] != ']' {
			return "", "", false, errors.New("missing ]")
		}
		ip = ip[1 : len(ip)-1]
		v6 = true
	}

	return ip, port, v6, nil
}

// ParseAddrPort parses s as an [AddrPort].
//
// It doesn't do any name resolution: both the address and the port
// must be numeric.
func ParseAddrPort(s string) (AddrPort, error) {
	var ipp AddrPort
	ip, port, v6, err := splitAddrPort(s)
	if err != nil {
		return ipp, err
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return ipp, errors.New("invalid port " + strconv.Quote(port) + " parsing " + strconv.Quote(s))
	}
	ipp.port = uint16(port16)
	ipp.ip, err = ParseAddr(ip)
	if err != nil {
		return AddrPort{}, err
	}
	if v6 && ipp.ip.Is4() {
		return AddrPort{}, errors.New("invalid ip:port " + strconv.Quote(s) + ", square brackets can only be used with IPv6 addresses")
	} else if !v6 && ipp.ip.Is6() {
		return AddrPort{}, errors.New("invalid ip:port " + strconv.Quote(s) + ", IPv6 addresses must be surrounded by square brackets")
	}
	return ipp, nil
}

// MustParseAddrPort calls [ParseAddrPort](s) and panics on error.
// It is intended for use in tests with hard-coded strings.
func MustParseAddrPort(s string) AddrPort {
	ip, err := ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ip
}

// IsValid reports whether p.Addr() is valid.
// All ports are valid, including zero.
func (p AddrPort) IsValid() bool { return p.ip.IsValid() }

// Compare returns an integer comparing two AddrPorts.
// The result will be 0 if p == p2, -1 if p < p2, and +1 if p > p2.
// AddrPorts sort first by IP address, then port.
func (p AddrPort) Compare(p2 AddrPort) int {
	if c := p.Addr().Compare(p2.Addr()); c != 0 {
		return c
	}
	return cmp.Compare(p.Port(), p2.Port())
}

func (p AddrPort) String()
```