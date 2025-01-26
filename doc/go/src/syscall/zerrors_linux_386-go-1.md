Response:
The user wants me to summarize the functionality of the provided Go code snippet, which is the second part of a `zerrors_linux_386.go` file. This file likely defines platform-specific constants, errors, and signals for the Linux 386 architecture within the `syscall` package in Go.

**Plan:**

1. **Identify the main sections:** The code is clearly divided into constants for various categories, error numbers, and signal numbers, followed by string arrays mapping error and signal numbers to their descriptions.
2. **Summarize the purpose of each section:** Explain what kind of constants are defined (e.g., networking flags, routing messages, socket options, file mode bits, terminal control, TCP options), what the error and signal sections represent, and the role of the string arrays.
这是Go语言`syscall`包在Linux 386架构下定义错误和信号常量以及它们对应文本描述的第二部分。

**归纳其功能如下：**

该部分代码主要定义了以下内容：

1. **更多的系统调用相关的常量 (Constants):**  这部分延续了第一部分，定义了更多的、用于与Linux内核进行交互的常量。这些常量可以分为几个主要的类别：
    * **路由相关的常量 (RTCF_, RTF_, RTM_, RTNH_, RTPROT_, RT_CLASS_)**:  这些常量用于表示路由配置和管理相关的标志、消息类型、协议类型等。例如，`RTF_UP` 表示路由已启用，`RTM_NEWROUTE` 表示新增路由消息类型。
    * **Socket相关的常量 (SIOC..., SOCK_, SOL_, SO_)**: 这些常量用于控制和配置网络套接字的行为。例如，`SOCK_STREAM` 表示TCP流式套接字， `SO_REUSEADDR` 表示允许重用本地地址。 `SIOCGIFADDR` 这样的常量用于表示套接字ioctl操作的命令，例如获取接口地址。
    * **文件模式相关的常量 (S_IEXEC, S_IFBLK, 等)**: 这些常量用于表示文件的类型和访问权限。例如，`S_IFDIR` 表示目录文件，`S_IRUSR` 表示用户读权限。
    * **终端控制相关的常量 (TCIFLUSH, TIOCCBRK, 等)**: 这些常量用于控制终端的行为，例如刷新输入/输出缓冲区 (`TCIFLUSH`)，发送中断信号 (`TIOCCBRK`)。
    * **TCP选项相关的常量 (TCP_CONGESTION, TCP_CORK, 等)**: 这些常量用于设置TCP协议的特定行为，例如拥塞控制算法 (`TCP_CONGESTION`)，以及禁用Nagle算法 (`TCP_NODELAY`)。
    * **杂项常量 (WALL, WCLONE, 等)**:  还有一些其他的常量，比如与进程等待相关的标志 (`WEXITED`)。

2. **错误常量 (Errors):**  这部分定义了Linux系统常见的错误码常量，例如 `EACCES` (权限被拒绝), `ENOENT` (文件或目录不存在)。这些常量类型为 `Errno`，它在Go语言中用于表示系统错误。

3. **信号常量 (Signals):**  这部分定义了Linux系统支持的各种信号常量，例如 `SIGINT` (中断信号，通常由Ctrl+C触发), `SIGKILL` (强制终止信号)。这些常量类型为 `Signal`。

4. **错误信息表 (Error table):**  这是一个字符串数组 `errors`，它将上面定义的错误常量值映射到对应的文本描述，方便程序在遇到错误时输出可读的信息。

5. **信号信息表 (Signal table):** 这是一个字符串数组 `signals`，它将上面定义的信号常量值映射到对应的文本描述。

总的来说，`go/src/syscall/zerrors_linux_386.go` 这个文件的作用是为Go程序在Linux 386架构下进行系统调用提供必要的常量定义，包括错误码、信号以及其他与操作系统交互相关的标志。这使得Go程序能够以类型安全且易于理解的方式与底层操作系统进行交互。

Prompt: 
```
这是路径为go/src/syscall/zerrors_linux_386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
          = 0x4000000
	RTCF_DOREDIRECT                  = 0x1000000
	RTCF_LOG                         = 0x2000000
	RTCF_MASQ                        = 0x400000
	RTCF_NAT                         = 0x800000
	RTCF_VALVE                       = 0x200000
	RTF_ADDRCLASSMASK                = 0xf8000000
	RTF_ADDRCONF                     = 0x40000
	RTF_ALLONLINK                    = 0x20000
	RTF_BROADCAST                    = 0x10000000
	RTF_CACHE                        = 0x1000000
	RTF_DEFAULT                      = 0x10000
	RTF_DYNAMIC                      = 0x10
	RTF_FLOW                         = 0x2000000
	RTF_GATEWAY                      = 0x2
	RTF_HOST                         = 0x4
	RTF_INTERFACE                    = 0x40000000
	RTF_IRTT                         = 0x100
	RTF_LINKRT                       = 0x100000
	RTF_LOCAL                        = 0x80000000
	RTF_MODIFIED                     = 0x20
	RTF_MSS                          = 0x40
	RTF_MTU                          = 0x40
	RTF_MULTICAST                    = 0x20000000
	RTF_NAT                          = 0x8000000
	RTF_NOFORWARD                    = 0x1000
	RTF_NONEXTHOP                    = 0x200000
	RTF_NOPMTUDISC                   = 0x4000
	RTF_POLICY                       = 0x4000000
	RTF_REINSTATE                    = 0x8
	RTF_REJECT                       = 0x200
	RTF_STATIC                       = 0x400
	RTF_THROW                        = 0x2000
	RTF_UP                           = 0x1
	RTF_WINDOW                       = 0x80
	RTF_XRESOLVE                     = 0x800
	RTM_BASE                         = 0x10
	RTM_DELACTION                    = 0x31
	RTM_DELADDR                      = 0x15
	RTM_DELADDRLABEL                 = 0x49
	RTM_DELLINK                      = 0x11
	RTM_DELNEIGH                     = 0x1d
	RTM_DELQDISC                     = 0x25
	RTM_DELROUTE                     = 0x19
	RTM_DELRULE                      = 0x21
	RTM_DELTCLASS                    = 0x29
	RTM_DELTFILTER                   = 0x2d
	RTM_F_CLONED                     = 0x200
	RTM_F_EQUALIZE                   = 0x400
	RTM_F_NOTIFY                     = 0x100
	RTM_F_PREFIX                     = 0x800
	RTM_GETACTION                    = 0x32
	RTM_GETADDR                      = 0x16
	RTM_GETADDRLABEL                 = 0x4a
	RTM_GETANYCAST                   = 0x3e
	RTM_GETDCB                       = 0x4e
	RTM_GETLINK                      = 0x12
	RTM_GETMULTICAST                 = 0x3a
	RTM_GETNEIGH                     = 0x1e
	RTM_GETNEIGHTBL                  = 0x42
	RTM_GETQDISC                     = 0x26
	RTM_GETROUTE                     = 0x1a
	RTM_GETRULE                      = 0x22
	RTM_GETTCLASS                    = 0x2a
	RTM_GETTFILTER                   = 0x2e
	RTM_MAX                          = 0x4f
	RTM_NEWACTION                    = 0x30
	RTM_NEWADDR                      = 0x14
	RTM_NEWADDRLABEL                 = 0x48
	RTM_NEWLINK                      = 0x10
	RTM_NEWNDUSEROPT                 = 0x44
	RTM_NEWNEIGH                     = 0x1c
	RTM_NEWNEIGHTBL                  = 0x40
	RTM_NEWPREFIX                    = 0x34
	RTM_NEWQDISC                     = 0x24
	RTM_NEWROUTE                     = 0x18
	RTM_NEWRULE                      = 0x20
	RTM_NEWTCLASS                    = 0x28
	RTM_NEWTFILTER                   = 0x2c
	RTM_NR_FAMILIES                  = 0x10
	RTM_NR_MSGTYPES                  = 0x40
	RTM_SETDCB                       = 0x4f
	RTM_SETLINK                      = 0x13
	RTM_SETNEIGHTBL                  = 0x43
	RTNH_ALIGNTO                     = 0x4
	RTNH_F_DEAD                      = 0x1
	RTNH_F_ONLINK                    = 0x4
	RTNH_F_PERVASIVE                 = 0x2
	RTN_MAX                          = 0xb
	RTPROT_BIRD                      = 0xc
	RTPROT_BOOT                      = 0x3
	RTPROT_DHCP                      = 0x10
	RTPROT_DNROUTED                  = 0xd
	RTPROT_GATED                     = 0x8
	RTPROT_KERNEL                    = 0x2
	RTPROT_MRT                       = 0xa
	RTPROT_NTK                       = 0xf
	RTPROT_RA                        = 0x9
	RTPROT_REDIRECT                  = 0x1
	RTPROT_STATIC                    = 0x4
	RTPROT_UNSPEC                    = 0x0
	RTPROT_XORP                      = 0xe
	RTPROT_ZEBRA                     = 0xb
	RT_CLASS_DEFAULT                 = 0xfd
	RT_CLASS_LOCAL                   = 0xff
	RT_CLASS_MAIN                    = 0xfe
	RT_CLASS_MAX                     = 0xff
	RT_CLASS_UNSPEC                  = 0x0
	RUSAGE_CHILDREN                  = -0x1
	RUSAGE_SELF                      = 0x0
	RUSAGE_THREAD                    = 0x1
	SCM_CREDENTIALS                  = 0x2
	SCM_RIGHTS                       = 0x1
	SCM_TIMESTAMP                    = 0x1d
	SCM_TIMESTAMPING                 = 0x25
	SCM_TIMESTAMPNS                  = 0x23
	SHUT_RD                          = 0x0
	SHUT_RDWR                        = 0x2
	SHUT_WR                          = 0x1
	SIOCADDDLCI                      = 0x8980
	SIOCADDMULTI                     = 0x8931
	SIOCADDRT                        = 0x890b
	SIOCATMARK                       = 0x8905
	SIOCDARP                         = 0x8953
	SIOCDELDLCI                      = 0x8981
	SIOCDELMULTI                     = 0x8932
	SIOCDELRT                        = 0x890c
	SIOCDEVPRIVATE                   = 0x89f0
	SIOCDIFADDR                      = 0x8936
	SIOCDRARP                        = 0x8960
	SIOCGARP                         = 0x8954
	SIOCGIFADDR                      = 0x8915
	SIOCGIFBR                        = 0x8940
	SIOCGIFBRDADDR                   = 0x8919
	SIOCGIFCONF                      = 0x8912
	SIOCGIFCOUNT                     = 0x8938
	SIOCGIFDSTADDR                   = 0x8917
	SIOCGIFENCAP                     = 0x8925
	SIOCGIFFLAGS                     = 0x8913
	SIOCGIFHWADDR                    = 0x8927
	SIOCGIFINDEX                     = 0x8933
	SIOCGIFMAP                       = 0x8970
	SIOCGIFMEM                       = 0x891f
	SIOCGIFMETRIC                    = 0x891d
	SIOCGIFMTU                       = 0x8921
	SIOCGIFNAME                      = 0x8910
	SIOCGIFNETMASK                   = 0x891b
	SIOCGIFPFLAGS                    = 0x8935
	SIOCGIFSLAVE                     = 0x8929
	SIOCGIFTXQLEN                    = 0x8942
	SIOCGPGRP                        = 0x8904
	SIOCGRARP                        = 0x8961
	SIOCGSTAMP                       = 0x8906
	SIOCGSTAMPNS                     = 0x8907
	SIOCPROTOPRIVATE                 = 0x89e0
	SIOCRTMSG                        = 0x890d
	SIOCSARP                         = 0x8955
	SIOCSIFADDR                      = 0x8916
	SIOCSIFBR                        = 0x8941
	SIOCSIFBRDADDR                   = 0x891a
	SIOCSIFDSTADDR                   = 0x8918
	SIOCSIFENCAP                     = 0x8926
	SIOCSIFFLAGS                     = 0x8914
	SIOCSIFHWADDR                    = 0x8924
	SIOCSIFHWBROADCAST               = 0x8937
	SIOCSIFLINK                      = 0x8911
	SIOCSIFMAP                       = 0x8971
	SIOCSIFMEM                       = 0x8920
	SIOCSIFMETRIC                    = 0x891e
	SIOCSIFMTU                       = 0x8922
	SIOCSIFNAME                      = 0x8923
	SIOCSIFNETMASK                   = 0x891c
	SIOCSIFPFLAGS                    = 0x8934
	SIOCSIFSLAVE                     = 0x8930
	SIOCSIFTXQLEN                    = 0x8943
	SIOCSPGRP                        = 0x8902
	SIOCSRARP                        = 0x8962
	SOCK_CLOEXEC                     = 0x80000
	SOCK_DCCP                        = 0x6
	SOCK_DGRAM                       = 0x2
	SOCK_NONBLOCK                    = 0x800
	SOCK_PACKET                      = 0xa
	SOCK_RAW                         = 0x3
	SOCK_RDM                         = 0x4
	SOCK_SEQPACKET                   = 0x5
	SOCK_STREAM                      = 0x1
	SOL_AAL                          = 0x109
	SOL_ATM                          = 0x108
	SOL_DECNET                       = 0x105
	SOL_ICMPV6                       = 0x3a
	SOL_IP                           = 0x0
	SOL_IPV6                         = 0x29
	SOL_IRDA                         = 0x10a
	SOL_PACKET                       = 0x107
	SOL_RAW                          = 0xff
	SOL_SOCKET                       = 0x1
	SOL_TCP                          = 0x6
	SOL_X25                          = 0x106
	SOMAXCONN                        = 0x80
	SO_ACCEPTCONN                    = 0x1e
	SO_ATTACH_FILTER                 = 0x1a
	SO_BINDTODEVICE                  = 0x19
	SO_BROADCAST                     = 0x6
	SO_BSDCOMPAT                     = 0xe
	SO_DEBUG                         = 0x1
	SO_DETACH_FILTER                 = 0x1b
	SO_DOMAIN                        = 0x27
	SO_DONTROUTE                     = 0x5
	SO_ERROR                         = 0x4
	SO_KEEPALIVE                     = 0x9
	SO_LINGER                        = 0xd
	SO_MARK                          = 0x24
	SO_NO_CHECK                      = 0xb
	SO_OOBINLINE                     = 0xa
	SO_PASSCRED                      = 0x10
	SO_PASSSEC                       = 0x22
	SO_PEERCRED                      = 0x11
	SO_PEERNAME                      = 0x1c
	SO_PEERSEC                       = 0x1f
	SO_PRIORITY                      = 0xc
	SO_PROTOCOL                      = 0x26
	SO_RCVBUF                        = 0x8
	SO_RCVBUFFORCE                   = 0x21
	SO_RCVLOWAT                      = 0x12
	SO_RCVTIMEO                      = 0x14
	SO_REUSEADDR                     = 0x2
	SO_RXQ_OVFL                      = 0x28
	SO_SECURITY_AUTHENTICATION       = 0x16
	SO_SECURITY_ENCRYPTION_NETWORK   = 0x18
	SO_SECURITY_ENCRYPTION_TRANSPORT = 0x17
	SO_SNDBUF                        = 0x7
	SO_SNDBUFFORCE                   = 0x20
	SO_SNDLOWAT                      = 0x13
	SO_SNDTIMEO                      = 0x15
	SO_TIMESTAMP                     = 0x1d
	SO_TIMESTAMPING                  = 0x25
	SO_TIMESTAMPNS                   = 0x23
	SO_TYPE                          = 0x3
	S_BLKSIZE                        = 0x200
	S_IEXEC                          = 0x40
	S_IFBLK                          = 0x6000
	S_IFCHR                          = 0x2000
	S_IFDIR                          = 0x4000
	S_IFIFO                          = 0x1000
	S_IFLNK                          = 0xa000
	S_IFMT                           = 0xf000
	S_IFREG                          = 0x8000
	S_IFSOCK                         = 0xc000
	S_IREAD                          = 0x100
	S_IRGRP                          = 0x20
	S_IROTH                          = 0x4
	S_IRUSR                          = 0x100
	S_IRWXG                          = 0x38
	S_IRWXO                          = 0x7
	S_IRWXU                          = 0x1c0
	S_ISGID                          = 0x400
	S_ISUID                          = 0x800
	S_ISVTX                          = 0x200
	S_IWGRP                          = 0x10
	S_IWOTH                          = 0x2
	S_IWRITE                         = 0x80
	S_IWUSR                          = 0x80
	S_IXGRP                          = 0x8
	S_IXOTH                          = 0x1
	S_IXUSR                          = 0x40
	TCIFLUSH                         = 0x0
	TCIOFLUSH                        = 0x2
	TCOFLUSH                         = 0x1
	TCP_CONGESTION                   = 0xd
	TCP_CORK                         = 0x3
	TCP_DEFER_ACCEPT                 = 0x9
	TCP_INFO                         = 0xb
	TCP_KEEPCNT                      = 0x6
	TCP_KEEPIDLE                     = 0x4
	TCP_KEEPINTVL                    = 0x5
	TCP_LINGER2                      = 0x8
	TCP_MAXSEG                       = 0x2
	TCP_MAXWIN                       = 0xffff
	TCP_MAX_WINSHIFT                 = 0xe
	TCP_MD5SIG                       = 0xe
	TCP_MD5SIG_MAXKEYLEN             = 0x50
	TCP_MSS                          = 0x200
	TCP_NODELAY                      = 0x1
	TCP_QUICKACK                     = 0xc
	TCP_SYNCNT                       = 0x7
	TCP_WINDOW_CLAMP                 = 0xa
	TIOCCBRK                         = 0x5428
	TIOCCONS                         = 0x541d
	TIOCEXCL                         = 0x540c
	TIOCGDEV                         = 0x80045432
	TIOCGETD                         = 0x5424
	TIOCGICOUNT                      = 0x545d
	TIOCGLCKTRMIOS                   = 0x5456
	TIOCGPGRP                        = 0x540f
	TIOCGPTN                         = 0x80045430
	TIOCGRS485                       = 0x542e
	TIOCGSERIAL                      = 0x541e
	TIOCGSID                         = 0x5429
	TIOCGSOFTCAR                     = 0x5419
	TIOCGWINSZ                       = 0x5413
	TIOCINQ                          = 0x541b
	TIOCLINUX                        = 0x541c
	TIOCMBIC                         = 0x5417
	TIOCMBIS                         = 0x5416
	TIOCMGET                         = 0x5415
	TIOCMIWAIT                       = 0x545c
	TIOCMSET                         = 0x5418
	TIOCM_CAR                        = 0x40
	TIOCM_CD                         = 0x40
	TIOCM_CTS                        = 0x20
	TIOCM_DSR                        = 0x100
	TIOCM_DTR                        = 0x2
	TIOCM_LE                         = 0x1
	TIOCM_RI                         = 0x80
	TIOCM_RNG                        = 0x80
	TIOCM_RTS                        = 0x4
	TIOCM_SR                         = 0x10
	TIOCM_ST                         = 0x8
	TIOCNOTTY                        = 0x5422
	TIOCNXCL                         = 0x540d
	TIOCOUTQ                         = 0x5411
	TIOCPKT                          = 0x5420
	TIOCPKT_DATA                     = 0x0
	TIOCPKT_DOSTOP                   = 0x20
	TIOCPKT_FLUSHREAD                = 0x1
	TIOCPKT_FLUSHWRITE               = 0x2
	TIOCPKT_IOCTL                    = 0x40
	TIOCPKT_NOSTOP                   = 0x10
	TIOCPKT_START                    = 0x8
	TIOCPKT_STOP                     = 0x4
	TIOCSBRK                         = 0x5427
	TIOCSCTTY                        = 0x540e
	TIOCSERCONFIG                    = 0x5453
	TIOCSERGETLSR                    = 0x5459
	TIOCSERGETMULTI                  = 0x545a
	TIOCSERGSTRUCT                   = 0x5458
	TIOCSERGWILD                     = 0x5454
	TIOCSERSETMULTI                  = 0x545b
	TIOCSERSWILD                     = 0x5455
	TIOCSER_TEMT                     = 0x1
	TIOCSETD                         = 0x5423
	TIOCSIG                          = 0x40045436
	TIOCSLCKTRMIOS                   = 0x5457
	TIOCSPGRP                        = 0x5410
	TIOCSPTLCK                       = 0x40045431
	TIOCSRS485                       = 0x542f
	TIOCSSERIAL                      = 0x541f
	TIOCSSOFTCAR                     = 0x541a
	TIOCSTI                          = 0x5412
	TIOCSWINSZ                       = 0x5414
	TUNATTACHFILTER                  = 0x400854d5
	TUNDETACHFILTER                  = 0x400854d6
	TUNGETFEATURES                   = 0x800454cf
	TUNGETIFF                        = 0x800454d2
	TUNGETSNDBUF                     = 0x800454d3
	TUNGETVNETHDRSZ                  = 0x800454d7
	TUNSETDEBUG                      = 0x400454c9
	TUNSETGROUP                      = 0x400454ce
	TUNSETIFF                        = 0x400454ca
	TUNSETLINK                       = 0x400454cd
	TUNSETNOCSUM                     = 0x400454c8
	TUNSETOFFLOAD                    = 0x400454d0
	TUNSETOWNER                      = 0x400454cc
	TUNSETPERSIST                    = 0x400454cb
	TUNSETSNDBUF                     = 0x400454d4
	TUNSETTXFILTER                   = 0x400454d1
	TUNSETVNETHDRSZ                  = 0x400454d8
	WALL                             = 0x40000000
	WCLONE                           = 0x80000000
	WCONTINUED                       = 0x8
	WEXITED                          = 0x4
	WNOHANG                          = 0x1
	WNOTHREAD                        = 0x20000000
	WNOWAIT                          = 0x1000000
	WORDSIZE                         = 0x20
	WSTOPPED                         = 0x2
	WUNTRACED                        = 0x2
)

// Errors
const (
	E2BIG           = Errno(0x7)
	EACCES          = Errno(0xd)
	EADDRINUSE      = Errno(0x62)
	EADDRNOTAVAIL   = Errno(0x63)
	EADV            = Errno(0x44)
	EAFNOSUPPORT    = Errno(0x61)
	EAGAIN          = Errno(0xb)
	EALREADY        = Errno(0x72)
	EBADE           = Errno(0x34)
	EBADF           = Errno(0x9)
	EBADFD          = Errno(0x4d)
	EBADMSG         = Errno(0x4a)
	EBADR           = Errno(0x35)
	EBADRQC         = Errno(0x38)
	EBADSLT         = Errno(0x39)
	EBFONT          = Errno(0x3b)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x7d)
	ECHILD          = Errno(0xa)
	ECHRNG          = Errno(0x2c)
	ECOMM           = Errno(0x46)
	ECONNABORTED    = Errno(0x67)
	ECONNREFUSED    = Errno(0x6f)
	ECONNRESET      = Errno(0x68)
	EDEADLK         = Errno(0x23)
	EDEADLOCK       = Errno(0x23)
	EDESTADDRREQ    = Errno(0x59)
	EDOM            = Errno(0x21)
	EDOTDOT         = Errno(0x49)
	EDQUOT          = Errno(0x7a)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EHOSTDOWN       = Errno(0x70)
	EHOSTUNREACH    = Errno(0x71)
	EIDRM           = Errno(0x2b)
	EILSEQ          = Errno(0x54)
	EINPROGRESS     = Errno(0x73)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EISCONN         = Errno(0x6a)
	EISDIR          = Errno(0x15)
	EISNAM          = Errno(0x78)
	EKEYEXPIRED     = Errno(0x7f)
	EKEYREJECTED    = Errno(0x81)
	EKEYREVOKED     = Errno(0x80)
	EL2HLT          = Errno(0x33)
	EL2NSYNC        = Errno(0x2d)
	EL3HLT          = Errno(0x2e)
	EL3RST          = Errno(0x2f)
	ELIBACC         = Errno(0x4f)
	ELIBBAD         = Errno(0x50)
	ELIBEXEC        = Errno(0x53)
	ELIBMAX         = Errno(0x52)
	ELIBSCN         = Errno(0x51)
	ELNRNG          = Errno(0x30)
	ELOOP           = Errno(0x28)
	EMEDIUMTYPE     = Errno(0x7c)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x5a)
	EMULTIHOP       = Errno(0x48)
	ENAMETOOLONG    = Errno(0x24)
	ENAVAIL         = Errno(0x77)
	ENETDOWN        = Errno(0x64)
	ENETRESET       = Errno(0x66)
	ENETUNREACH     = Errno(0x65)
	ENFILE          = Errno(0x17)
	ENOANO          = Errno(0x37)
	ENOBUFS         = Errno(0x69)
	ENOCSI          = Errno(0x32)
	ENODATA         = Errno(0x3d)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOKEY          = Errno(0x7e)
	ENOLCK          = Errno(0x25)
	ENOLINK         = Errno(0x43)
	ENOMEDIUM       = Errno(0x7b)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x2a)
	ENONET          = Errno(0x40)
	ENOPKG          = Errno(0x41)
	ENOPROTOOPT     = Errno(0x5c)
	ENOSPC          = Errno(0x1c)
	ENOSR           = Errno(0x3f)
	ENOSTR          = Errno(0x3c)
	ENOSYS          = Errno(0x26)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x6b)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x27)
	ENOTNAM         = Errno(0x76)
	ENOTRECOVERABLE = Errno(0x83)
	ENOTSOCK        = Errno(0x58)
	ENOTSUP         = Errno(0x5f)
	ENOTTY          = Errno(0x19)
	ENOTUNIQ        = Errno(0x4c)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x5f)
	EOVERFLOW       = Errno(0x4b)
	EOWNERDEAD      = Errno(0x82)
	EPERM           = Errno(0x1)
	EPFNOSUPPORT    = Errno(0x60)
	EPIPE           = Errno(0x20)
	EPROTO          = Errno(0x47)
	EPROTONOSUPPORT = Errno(0x5d)
	EPROTOTYPE      = Errno(0x5b)
	ERANGE          = Errno(0x22)
	EREMCHG         = Errno(0x4e)
	EREMOTE         = Errno(0x42)
	EREMOTEIO       = Errno(0x79)
	ERESTART        = Errno(0x55)
	ERFKILL         = Errno(0x84)
	EROFS           = Errno(0x1e)
	ESHUTDOWN       = Errno(0x6c)
	ESOCKTNOSUPPORT = Errno(0x5e)
	ESPIPE          = Errno(0x1d)
	ESRCH           = Errno(0x3)
	ESRMNT          = Errno(0x45)
	ESTALE          = Errno(0x74)
	ESTRPIPE        = Errno(0x56)
	ETIME           = Errno(0x3e)
	ETIMEDOUT       = Errno(0x6e)
	ETOOMANYREFS    = Errno(0x6d)
	ETXTBSY         = Errno(0x1a)
	EUCLEAN         = Errno(0x75)
	EUNATCH         = Errno(0x31)
	EUSERS          = Errno(0x57)
	EWOULDBLOCK     = Errno(0xb)
	EXDEV           = Errno(0x12)
	EXFULL          = Errno(0x36)
)

// Signals
const (
	SIGABRT   = Signal(0x6)
	SIGALRM   = Signal(0xe)
	SIGBUS    = Signal(0x7)
	SIGCHLD   = Signal(0x11)
	SIGCLD    = Signal(0x11)
	SIGCONT   = Signal(0x12)
	SIGFPE    = Signal(0x8)
	SIGHUP    = Signal(0x1)
	SIGILL    = Signal(0x4)
	SIGINT    = Signal(0x2)
	SIGIO     = Signal(0x1d)
	SIGIOT    = Signal(0x6)
	SIGKILL   = Signal(0x9)
	SIGPIPE   = Signal(0xd)
	SIGPOLL   = Signal(0x1d)
	SIGPROF   = Signal(0x1b)
	SIGPWR    = Signal(0x1e)
	SIGQUIT   = Signal(0x3)
	SIGSEGV   = Signal(0xb)
	SIGSTKFLT = Signal(0x10)
	SIGSTOP   = Signal(0x13)
	SIGSYS    = Signal(0x1f)
	SIGTERM   = Signal(0xf)
	SIGTRAP   = Signal(0x5)
	SIGTSTP   = Signal(0x14)
	SIGTTIN   = Signal(0x15)
	SIGTTOU   = Signal(0x16)
	SIGUNUSED = Signal(0x1f)
	SIGURG    = Signal(0x17)
	SIGUSR1   = Signal(0xa)
	SIGUSR2   = Signal(0xc)
	SIGVTALRM = Signal(0x1a)
	SIGWINCH  = Signal(0x1c)
	SIGXCPU   = Signal(0x18)
	SIGXFSZ   = Signal(0x19)
)

// Error table
var errors = [...]string{
	1:   "operation not permitted",
	2:   "no such file or directory",
	3:   "no such process",
	4:   "interrupted system call",
	5:   "input/output error",
	6:   "no such device or address",
	7:   "argument list too long",
	8:   "exec format error",
	9:   "bad file descriptor",
	10:  "no child processes",
	11:  "resource temporarily unavailable",
	12:  "cannot allocate memory",
	13:  "permission denied",
	14:  "bad address",
	15:  "block device required",
	16:  "device or resource busy",
	17:  "file exists",
	18:  "invalid cross-device link",
	19:  "no such device",
	20:  "not a directory",
	21:  "is a directory",
	22:  "invalid argument",
	23:  "too many open files in system",
	24:  "too many open files",
	25:  "inappropriate ioctl for device",
	26:  "text file busy",
	27:  "file too large",
	28:  "no space left on device",
	29:  "illegal seek",
	30:  "read-only file system",
	31:  "too many links",
	32:  "broken pipe",
	33:  "numerical argument out of domain",
	34:  "numerical result out of range",
	35:  "resource deadlock avoided",
	36:  "file name too long",
	37:  "no locks available",
	38:  "function not implemented",
	39:  "directory not empty",
	40:  "too many levels of symbolic links",
	42:  "no message of desired type",
	43:  "identifier removed",
	44:  "channel number out of range",
	45:  "level 2 not synchronized",
	46:  "level 3 halted",
	47:  "level 3 reset",
	48:  "link number out of range",
	49:  "protocol driver not attached",
	50:  "no CSI structure available",
	51:  "level 2 halted",
	52:  "invalid exchange",
	53:  "invalid request descriptor",
	54:  "exchange full",
	55:  "no anode",
	56:  "invalid request code",
	57:  "invalid slot",
	59:  "bad font file format",
	60:  "device not a stream",
	61:  "no data available",
	62:  "timer expired",
	63:  "out of streams resources",
	64:  "machine is not on the network",
	65:  "package not installed",
	66:  "object is remote",
	67:  "link has been severed",
	68:  "advertise error",
	69:  "srmount error",
	70:  "communication error on send",
	71:  "protocol error",
	72:  "multihop attempted",
	73:  "RFS specific error",
	74:  "bad message",
	75:  "value too large for defined data type",
	76:  "name not unique on network",
	77:  "file descriptor in bad state",
	78:  "remote address changed",
	79:  "can not access a needed shared library",
	80:  "accessing a corrupted shared library",
	81:  ".lib section in a.out corrupted",
	82:  "attempting to link in too many shared libraries",
	83:  "cannot exec a shared library directly",
	84:  "invalid or incomplete multibyte or wide character",
	85:  "interrupted system call should be restarted",
	86:  "streams pipe error",
	87:  "too many users",
	88:  "socket operation on non-socket",
	89:  "destination address required",
	90:  "message too long",
	91:  "protocol wrong type for socket",
	92:  "protocol not available",
	93:  "protocol not supported",
	94:  "socket type not supported",
	95:  "operation not supported",
	96:  "protocol family not supported",
	97:  "address family not supported by protocol",
	98:  "address already in use",
	99:  "cannot assign requested address",
	100: "network is down",
	101: "network is unreachable",
	102: "network dropped connection on reset",
	103: "software caused connection abort",
	104: "connection reset by peer",
	105: "no buffer space available",
	106: "transport endpoint is already connected",
	107: "transport endpoint is not connected",
	108: "cannot send after transport endpoint shutdown",
	109: "too many references: cannot splice",
	110: "connection timed out",
	111: "connection refused",
	112: "host is down",
	113: "no route to host",
	114: "operation already in progress",
	115: "operation now in progress",
	116: "stale NFS file handle",
	117: "structure needs cleaning",
	118: "not a XENIX named type file",
	119: "no XENIX semaphores available",
	120: "is a named type file",
	121: "remote I/O error",
	122: "disk quota exceeded",
	123: "no medium found",
	124: "wrong medium type",
	125: "operation canceled",
	126: "required key not available",
	127: "key has expired",
	128: "key has been revoked",
	129: "key was rejected by service",
	130: "owner died",
	131: "state not recoverable",
	132: "operation not possible due to RF-kill",
}

// Signal table
var signals = [...]string{
	1:  "hangup",
	2:  "interrupt",
	3:  "quit",
	4:  "illegal instruction",
	5:  "trace/breakpoint trap",
	6:  "aborted",
	7:  "bus error",
	8:  "floating point exception",
	9:  "killed",
	10: "user defined signal 1",
	11: "segmentation fault",
	12: "user defined signal 2",
	13: "broken pipe",
	14: "alarm clock",
	15: "terminated",
	16: "stack fault",
	17: "child exited",
	18: "continued",
	19: "stopped (signal)",
	20: "stopped",
	21: "stopped (tty input)",
	22: "stopped (tty output)",
	23: "urgent I/O condition",
	24: "CPU time limit exceeded",
	25: "file size limit exceeded",
	26: "virtual timer expired",
	27: "profiling timer expired",
	28: "window changed",
	29: "I/O possible",
	30: "power failure",
	31: "bad system call",
}

"""




```