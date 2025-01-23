Response:
### 功能概述

`p2p.vala` 文件是 Frida 动态插桩工具中用于处理点对点（P2P）通信的核心模块。它主要实现了以下功能：

1. **STUN/TURN 服务器配置**：
   - 通过 `configure_agent` 方法，配置 STUN（Session Traversal Utilities for NAT）和 TURN（Traversal Using Relays around NAT）服务器信息。这些服务器用于在 NAT（网络地址转换）环境下建立 P2P 连接。
   - 支持 UDP、TCP、TLS 三种类型的 TURN 服务器。

2. **证书指纹计算**：
   - `compute_certificate_fingerprint` 方法用于计算 DER 格式证书的 SHA-256 指纹，通常用于 WebRTC 等协议中的证书验证。

3. **SDP（Session Description Protocol）解析与生成**：
   - `PeerSessionDescription` 类用于解析和生成 SDP 消息，SDP 是 WebRTC 中用于描述媒体会话的协议。
   - 支持 ICE（Interactive Connectivity Establishment）相关的属性解析，如 `ice-ufrag`、`ice-pwd` 等。

4. **P2P 会话管理**：
   - `PeerSocket` 类封装了 P2P 通信的底层套接字操作，支持异步的 UDP 数据报发送和接收。
   - 通过 `Nice.Agent` 实现 ICE 协议，处理 NAT 穿透和连接建立。

5. **SCTP（Stream Control Transmission Protocol）连接管理**：
   - `SctpConnection` 类封装了 SCTP 协议的操作，支持可靠的数据传输。
   - 支持 WebRTC 数据通道（Data Channel）的打开、关闭和数据传输。

6. **证书生成**：
   - `generate_certificate` 方法用于生成自签名证书，通常用于 WebRTC 中的 DTLS（Datagram Transport Layer Security）加密。

### 二进制底层与 Linux 内核

1. **SCTP 协议**：
   - SCTP 是一种传输层协议，提供可靠的消息传输。在 Linux 内核中，SCTP 协议栈由内核模块实现，用户空间程序通过系统调用与内核交互。
   - 在 `SctpConnection` 类中，`_create_sctp_socket` 和 `_connect_sctp_socket` 方法可能调用了 Linux 内核的 SCTP 相关系统调用（如 `socket`、`bind`、`connect` 等）。

2. **ICE 协议**：
   - ICE 协议用于在 NAT 环境下建立 P2P 连接。`Nice.Agent` 是 libnice 库的一部分，libnice 是一个实现 ICE 协议的开源库。
   - `Nice.Agent` 通过 UDP 套接字与 STUN/TURN 服务器通信，处理 NAT 穿透。

### LLDB 调试示例

假设我们想要调试 `configure_agent` 方法，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令

```bash
# 启动 LLDB 并附加到 Frida 进程
lldb frida

# 设置断点
b p2p.vala:10  # 假设 configure_agent 方法在第 10 行

# 运行程序
run

# 当断点命中时，查看变量
frame variable
```

#### LLDB Python 脚本

```python
import lldb

def configure_agent_breakpoint(frame, bp_loc, dict):
    print("Breakpoint hit in configure_agent!")
    # 打印传入的参数
    agent = frame.FindVariable("agent")
    stream_id = frame.FindVariable("stream_id")
    component_id = frame.FindVariable("component_id")
    options = frame.FindVariable("options")
    print(f"agent: {agent}, stream_id: {stream_id}, component_id: {component_id}, options: {options}")
    return True

# 创建调试器实例
debugger = lldb.SBDebugger.Create()
debugger.SetAsync(False)

# 创建目标
target = debugger.CreateTarget("frida")

# 设置断点
breakpoint = target.BreakpointCreateByLocation("p2p.vala", 10)
breakpoint.SetScriptCallbackFunction("configure_agent_breakpoint")

# 运行程序
process = target.LaunchSimple(None, None, os.getcwd())
```

### 逻辑推理与输入输出

假设 `configure_agent` 方法的输入如下：

- `agent`: 一个 `Nice.Agent` 实例。
- `stream_id`: 流 ID，假设为 `1`。
- `component_id`: 组件 ID，假设为 `1`。
- `options`: 包含 STUN 服务器地址和 TURN 服务器信息的 `PeerOptions` 对象。

输出：
- 如果 STUN 服务器地址无效，抛出 `Error.INVALID_ARGUMENT` 异常。
- 如果配置成功，`agent` 的 STUN 服务器和 TURN 服务器信息将被更新。

### 常见用户错误

1. **STUN/TURN 服务器地址错误**：
   - 用户可能输入了无效的 STUN 或 TURN 服务器地址，导致 `configure_agent` 方法抛出 `Error.INVALID_ARGUMENT` 异常。
   - 示例：`stun_server = "invalid_address"`。

2. **证书生成失败**：
   - 在 `generate_certificate` 方法中，如果证书生成过程中出现错误（如内存不足），可能导致证书生成失败。
   - 示例：`generate_certificate` 返回的 `cert_der` 为空。

### 用户操作路径

1. **启动 Frida**：
   - 用户启动 Frida 工具，并加载目标应用程序。

2. **配置 P2P 连接**：
   - 用户调用 `configure_agent` 方法，传入 STUN/TURN 服务器地址和其他配置参数。

3. **建立连接**：
   - Frida 通过 `Nice.Agent` 与 STUN/TURN 服务器通信，建立 P2P 连接。

4. **数据传输**：
   - 用户通过 `PeerSocket` 或 `SctpConnection` 进行数据传输。

5. **调试与错误处理**：
   - 如果连接失败，用户可以通过调试工具（如 LLDB）查看 `configure_agent` 方法的执行情况，排查错误。

### 总结

`p2p.vala` 文件实现了 Frida 工具中 P2P 通信的核心功能，包括 STUN/TURN 服务器配置、SDP 解析、SCTP 连接管理等。通过 LLDB 调试工具，用户可以深入分析这些功能的执行过程，排查潜在的错误。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/lib/base/p2p.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```
#if HAVE_NICE
namespace Frida {
	namespace PeerConnection {
		public async void configure_agent (Nice.Agent agent, uint stream_id, uint component_id, PeerOptions? options,
				Cancellable? cancellable) throws Error, IOError {
			if (options == null)
				return;

			string? stun_server = options.stun_server;
			if (stun_server != null) {
				InetSocketAddress? addr;
				try {
					var enumerator = NetworkAddress.parse (stun_server, 3478).enumerate ();
					addr = (InetSocketAddress) yield enumerator.next_async (cancellable);
				} catch (GLib.Error e) {
					throw new Error.INVALID_ARGUMENT ("Invalid STUN server address: %s", e.message);
				}
				if (addr == null)
					throw new Error.INVALID_ARGUMENT ("Invalid STUN server address");
				agent.stun_server = addr.get_address ().to_string ();
				agent.stun_server_port = addr.get_port ();
			}

			var relays = new Gee.ArrayList<Relay> ();
			options.enumerate_relays (relay => {
				relays.add (relay);
			});
			foreach (var relay in relays) {
				InetSocketAddress? addr;
				try {
					var enumerator = NetworkAddress.parse (relay.address, 3478).enumerate ();
					addr = (InetSocketAddress) yield enumerator.next_async (cancellable);
				} catch (GLib.Error e) {
					throw new Error.INVALID_ARGUMENT ("Invalid relay server address: %s", e.message);
				}
				if (addr == null)
					throw new Error.INVALID_ARGUMENT ("Invalid relay server address");
				agent.set_relay_info (stream_id, component_id, addr.get_address ().to_string (),
					addr.get_port (), relay.username, relay.password, relay_kind_to_libnice (relay.kind));
			}
		}

		public string compute_certificate_fingerprint (uint8[] cert_der) {
			var fingerprint = new StringBuilder.sized (128);

			fingerprint.append ("sha-256 ");

			string raw_fingerprint = Checksum.compute_for_data (SHA256, cert_der);
			for (int offset = 0; offset != raw_fingerprint.length; offset += 2) {
				if (offset != 0)
					fingerprint.append_c (':');
				fingerprint.append_c (raw_fingerprint[offset + 0].toupper ());
				fingerprint.append_c (raw_fingerprint[offset + 1].toupper ());
			}

			return fingerprint.str;
		}

		private Nice.RelayType relay_kind_to_libnice (RelayKind kind) {
			switch (kind) {
				case TURN_UDP: return Nice.RelayType.TURN_UDP;
				case TURN_TCP: return Nice.RelayType.TURN_TCP;
				case TURN_TLS: return Nice.RelayType.TURN_TLS;
			}
			assert_not_reached ();
		}
	}

	public class PeerSessionDescription {
		public uint64 session_id = 0;
		public string? ice_ufrag;
		public string? ice_pwd;
		public bool ice_trickle = false;
		public string? fingerprint;
		public PeerSetup setup = HOLDCONN;
		public uint16 sctp_port = 5000;
		public size_t max_message_size = 256 * 1024;

		public static PeerSessionDescription parse (string sdp) throws Error {
			var description = new PeerSessionDescription ();

			foreach (unowned string raw_line in sdp.split ("\n")) {
				string line = raw_line.chomp ();
				if (line.has_prefix ("o=")) {
					string[] tokens = line[2:].split (" ", 6);
					if (tokens.length >= 2)
						description.session_id = uint64.parse (tokens[1]);
				} else if (line.has_prefix ("a=")) {
					string[] tokens = line[2:].split (":", 2);
					if (tokens.length == 2) {
						unowned string attribute = tokens[0];
						unowned string val = tokens[1];
						if (attribute == "ice-ufrag") {
							description.ice_ufrag = val;
						} else if (attribute == "ice-pwd") {
							description.ice_pwd = val;
						} else if (attribute == "ice-options") {
							string[] options = val.split (" ");
							foreach (unowned string option in options) {
								if (option == "trickle")
									description.ice_trickle = true;
							}
						} else if (attribute == "fingerprint") {
							description.fingerprint = val;
						} else if (attribute == "setup") {
							description.setup = PeerSetup.from_nick (val);
						} else if (attribute == "sctp-port") {
							description.sctp_port = (uint16) uint.parse (val);
						} else if (attribute == "max-message-size") {
							description.max_message_size = uint.parse (val);
						}
					}
				}
			}

			description.check ();

			return description;
		}

		public string to_sdp () {
			return string.join ("\r\n",
				"v=0",
				("o=- %" + uint64.FORMAT_MODIFIER + "u 2 IN IP4 127.0.0.1").printf (session_id),
				"s=-",
				"t=0 0",
				"a=group:BUNDLE 0",
				"a=extmap-allow-mixed",
				"a=msid-semantic: WMS",
				"m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
				"c=IN IP4 0.0.0.0",
				"a=ice-ufrag:" + ice_ufrag,
				"a=ice-pwd:" + ice_pwd,
				"a=ice-options:trickle",
				"a=fingerprint:" + fingerprint,
				"a=setup:" + setup.to_nick (),
				"a=mid:0",
				("a=sctp-port:%" + uint16.FORMAT_MODIFIER + "u").printf (sctp_port),
				("a=max-message-size:%" + size_t.FORMAT_MODIFIER + "u").printf (max_message_size)
			) + "\r\n";
		}

		private void check () throws Error {
			if (session_id == 0 || ice_ufrag == null || ice_pwd == null || !ice_trickle || fingerprint == null ||
					setup == HOLDCONN) {
				throw new Error.NOT_SUPPORTED ("Unsupported session configuration");
			}
		}
	}

	namespace PeerSessionId {
		public uint64 generate () {
			return ((uint64) Random.next_int ()) << 32 | (uint64) Random.next_int ();
		}
	}

	public enum PeerSetup {
		ACTIVE,
		PASSIVE,
		ACTPASS,
		HOLDCONN;

		public static PeerSetup from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<PeerSetup> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<PeerSetup> (this);
		}
	}

	public class PeerSocket : Object, DatagramBased {
		public Nice.Agent agent {
			get;
			construct;
		}

		public uint stream_id {
			get;
			construct;
		}

		public uint component_id {
			get;
			construct;
		}

		public MainContext? main_context {
			get;
			construct;
		}

		public IOCondition pending_io {
			get {
				mutex.lock ();
				IOCondition result = _pending_io;
				mutex.unlock ();
				return result;
			}
		}

		private Nice.ComponentState component_state;
		private RecvState recv_state = NOT_RECEIVING;
		private Gee.Queue<Bytes> recv_queue = new Gee.ArrayQueue<Bytes> ();
		private IOCondition _pending_io = 0;
		private Mutex mutex = Mutex ();
		private Cond cond = Cond ();

		private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

		private enum RecvState {
			NOT_RECEIVING,
			RECEIVING
		}

		public PeerSocket (Nice.Agent agent, uint stream_id, uint component_id) {
			Object (
				agent: agent,
				stream_id: stream_id,
				component_id: component_id,
				main_context: MainContext.get_thread_default ()
			);
		}

		construct {
			component_state = agent.get_component_state (stream_id, component_id);
			agent.component_state_changed.connect (on_component_state_changed);
		}

		public virtual int datagram_receive_messages (InputMessage[] messages, int flags, int64 timeout,
				Cancellable? cancellable) throws GLib.Error {
			if (flags != 0)
				throw new IOError.NOT_SUPPORTED ("Flags not supported");

			int64 deadline;
			prepare_for_io (timeout, cancellable, out deadline);

			int received = 0;
			GLib.Error? io_error = null;
			ulong cancellation_handler = 0;

			while (received != messages.length && io_error == null) {
				mutex.lock ();
				Bytes? bytes = recv_queue.poll ();
				update_pending_io ();
				mutex.unlock ();

				if (bytes != null) {
					messages[received].bytes_received = 0;
					messages[received].flags = 0;

					uint8 * data = bytes.get_data ();
					size_t remaining = bytes.get_size ();
					foreach (unowned InputVector vector in messages[received].vectors) {
						size_t n = size_t.min (remaining, vector.size);
						if (n == 0)
							break;
						Memory.copy (vector.buffer, data, n);
						data += n;
						remaining -= n;
						messages[received].bytes_received += n;
					}

					received++;
				} else {
					if (received > 0)
						break;

					if (deadline == 0) {
						io_error = new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
					} else if (deadline != -1 && get_monotonic_time () >= deadline) {
						io_error = new IOError.TIMED_OUT ("Timed out");
					} else {
						if (cancellable != null && cancellation_handler == 0) {
							cancellation_handler = cancellable.connect (() => {
								mutex.lock ();
								cond.broadcast ();
								mutex.unlock ();
							});
						}

						mutex.lock ();
						while (recv_queue.is_empty && !cancellable.is_cancelled ()) {
							if (deadline != -1) {
								if (!cond.wait_until (mutex, deadline)) {
									io_error = new IOError.TIMED_OUT ("Timed out");
									break;
								}
							} else {
								cond.wait (mutex);
							}
						}
						mutex.unlock ();
					}
				}
			}

			if (cancellation_handler != 0)
				cancellable.disconnect (cancellation_handler);

			if (received == 0 && io_error != null)
				throw io_error;

			return received;
		}

		public virtual int datagram_send_messages (OutputMessage[] messages, int flags, int64 timeout,
				Cancellable? cancellable) throws GLib.Error {
			if (flags != 0)
				throw new IOError.NOT_SUPPORTED ("Flags not supported");

			int64 deadline;
			prepare_for_io (timeout, cancellable, out deadline);

			var nice_messages = new Nice.OutputMessage[messages.length];
			for (var i = 0; i != messages.length; i++) {
				nice_messages[i].buffers = messages[i].vectors;
				nice_messages[i].n_buffers = (int) messages[i].num_vectors;
			}

			int sent = 0;
			GLib.Error? io_error = null;
			ulong cancellation_handler = 0;

			while (sent != nice_messages.length && io_error == null) {
				try {
					int n = agent.send_messages_nonblocking (stream_id, component_id, nice_messages[sent:],
						cancellable);
					sent += n;
				} catch (GLib.Error e) {
					if (sent > 0)
						break;

					if (e is IOError.WOULD_BLOCK && deadline != 0) {
						if (deadline != -1 && get_monotonic_time () >= deadline) {
							io_error = new IOError.TIMED_OUT ("Timed out");
							break;
						}

						if (cancellable != null && cancellation_handler == 0) {
							cancellation_handler = cancellable.connect (() => {
								mutex.lock ();
								cond.broadcast ();
								mutex.unlock ();
							});
						}

						int64 ten_msec_from_now = get_monotonic_time () + 10000;
						mutex.lock ();
						while (!cancellable.is_cancelled ()) {
							if (!cond.wait_until (mutex, (deadline != -1)
									? int64.min (ten_msec_from_now, deadline)
									: ten_msec_from_now)) {
								break;
							}
						}
						mutex.unlock ();
					} else {
						io_error = e;
					}
				}
			}

			if (cancellation_handler != 0)
				cancellable.disconnect (cancellation_handler);

			if (sent == 0 && io_error != null)
				throw io_error;

			foreach (var message in messages)
				message.bytes_sent = 0;
			for (int i = 0; i < sent; i++) {
				foreach (var vector in messages[i].vectors)
					messages[i].bytes_sent += (uint) vector.size;
			}

			return sent;
		}

		public virtual DatagramBasedSource datagram_create_source (IOCondition condition, Cancellable? cancellable) {
			return new PeerSocketSource (this, condition, cancellable);
		}

		public virtual IOCondition datagram_condition_check (IOCondition condition) {
			assert_not_reached ();
		}

		public virtual bool datagram_condition_wait (IOCondition condition, int64 timeout,
				Cancellable? cancellable) throws GLib.Error {
			assert_not_reached ();
		}

		public void register_source (Source source, IOCondition condition) {
			mutex.lock ();
			sources[source] = condition | IOCondition.ERR | IOCondition.HUP;
			mutex.unlock ();
		}

		public void unregister_source (Source source) {
			mutex.lock ();
			sources.unset (source);
			mutex.unlock ();
		}

		private void on_component_state_changed (uint stream_id, uint component_id, Nice.ComponentState state) {
			if (stream_id != this.stream_id || component_id != this.component_id)
				return;

			mutex.lock ();
			component_state = state;
			update_pending_io ();
			cond.broadcast ();
			mutex.unlock ();
		}

		private void on_recv (Nice.Agent agent, uint stream_id, uint component_id, uint8[] data) {
			var packet = new Bytes (data);

			mutex.lock ();
			recv_queue.offer (packet);
			update_pending_io ();
			cond.broadcast ();
			mutex.unlock ();
		}

		private void update_pending_io () {
			IOCondition condition = 0;

			if (!recv_queue.is_empty)
				condition |= IOCondition.IN;

			switch (component_state) {
				case CONNECTED:
				case READY:
					condition |= IOCondition.OUT;
					break;
				case FAILED:
					condition |= IOCondition.ERR;
					break;
				default:
					break;
			}

			if (condition == _pending_io)
				return;

			_pending_io = condition;

			foreach (var entry in sources.entries) {
				unowned Source source = entry.key;
				IOCondition c = entry.value;
				if ((_pending_io & c) != 0)
					source.set_ready_time (0);
			}
		}

		private void prepare_for_io (int64 timeout, Cancellable? cancellable, out int64 deadline) throws IOError {
			mutex.lock ();

			if (recv_state == NOT_RECEIVING) {
				recv_state = RECEIVING;
				mutex.unlock ();
				agent.attach_recv (stream_id, component_id, main_context, on_recv);
				mutex.lock ();
			}

			Nice.ComponentState current_state = component_state;
			bool timed_out = false;

			if (timeout != 0) {
				ulong cancellation_handler = 0;

				deadline = (timeout != -1)
					? get_monotonic_time () + timeout
					: -1;

				while (component_state != CONNECTED && component_state != READY && component_state != FAILED) {
					if (cancellable != null && cancellation_handler == 0) {
						mutex.unlock ();
						cancellation_handler = cancellable.connect (() => {
							mutex.lock ();
							cond.broadcast ();
							mutex.unlock ();
						});
						mutex.lock ();
					}

					if (cancellable.is_cancelled ())
						break;

					if (deadline != -1) {
						if (!cond.wait_until (mutex, deadline)) {
							timed_out = true;
							break;
						}
					} else {
						cond.wait (mutex);
					}
				}

				if (cancellation_handler != 0) {
					mutex.unlock ();
					cancellable.disconnect (cancellation_handler);
					mutex.lock ();
				}

				current_state = component_state;
			} else {
				deadline = 0;
			}

			mutex.unlock ();

			cancellable.set_error_if_cancelled ();

			if (current_state != CONNECTED && current_state != READY) {
				if (timed_out) {
					throw new IOError.TIMED_OUT ("Timed out");
				} else {
					if (timeout == 0 && current_state != FAILED)
						throw new IOError.WOULD_BLOCK ("Operation would block");
					else
						throw new IOError.HOST_UNREACHABLE ("Unable to send");
				}
			}
		}
	}

	private class PeerSocketSource : DatagramBasedSource {
		public PeerSocket socket;
		public IOCondition condition;
		public Cancellable? cancellable;

		public PeerSocketSource (PeerSocket socket, IOCondition condition, Cancellable? cancellable) {
			this.socket = socket;
			this.condition = condition;
			this.cancellable = cancellable;

			socket.register_source (this, condition);
		}

		~PeerSocketSource () {
			socket.unregister_source (this);
		}

		protected override bool prepare (out int timeout) {
			timeout = -1;
			return (socket.pending_io & condition) != 0;
		}

		protected override bool check () {
			return (socket.pending_io & condition) != 0;
		}

		protected override bool dispatch (SourceFunc? callback) {
			set_ready_time (-1);

			if (callback == null)
				return Source.REMOVE;

			DatagramBasedSourceFunc f = (DatagramBasedSourceFunc) callback;
			return f (socket, socket.pending_io);
		}
	}

	public class SctpConnection : IOStream {
		public DatagramBased transport_socket {
			get;
			construct;
		}

		public PeerSetup setup {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		public size_t max_message_size {
			get;
			construct;
		}

		public State state {
			get {
				return _state;
			}
		}

		public override InputStream input_stream {
			get {
				return _input_stream;
			}
		}

		public override OutputStream output_stream {
			get {
				return _output_stream;
			}
		}

		public IOCondition pending_io {
			get {
				lock (state)
					return sctp_events;
			}
		}

		private State _state = CREATED;
		private SctpInputStream _input_stream;
		private SctpOutputStream _output_stream;

		private DatagramBasedSource transport_source;
		private uint8[] transport_buffer = new uint8[65536];

		private void * sctp_socket;
		private IOCondition sctp_events = 0;
		private SctpTimerSource sctp_source;
		private uint16 stream_id;
		private ByteArray dcep_message = new ByteArray ();

		private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

		private Cancellable io_cancellable = new Cancellable ();

		public enum State {
			CREATED,
			OPENING,
			OPENED,
			CLOSED
		}

		public SctpConnection (DatagramBased transport_socket, PeerSetup setup, uint16 port, size_t max_message_size) {
			Object (
				transport_socket: transport_socket,
				setup: setup,
				port: port,
				max_message_size: max_message_size
			);
		}

		static construct {
			_initialize_sctp_backend ();
		}

		protected extern static void _initialize_sctp_backend ();

		construct {
			_input_stream = new SctpInputStream (this);
			_output_stream = new SctpOutputStream (this);

			sctp_socket = _create_sctp_socket ();
			_connect_sctp_socket (sctp_socket, port);

			var main_context = MainContext.get_thread_default ();

			transport_source = transport_socket.create_source (IOCondition.IN, io_cancellable);
			transport_source.set_callback (on_transport_socket_readable);
			transport_source.attach (main_context);

			sctp_source = new SctpTimerSource ();
			sctp_source.attach (main_context);
		}

		protected extern void * _create_sctp_socket ();

		protected extern void _connect_sctp_socket (void * sock, uint16 port);

		public override bool close (GLib.Cancellable? cancellable) throws IOError {
			do_close ();
			return true;
		}

		public override async bool close_async (int io_priority, GLib.Cancellable? cancellable) throws IOError {
			do_close ();
			return true;
		}

		private void do_close () {
			sctp_source.destroy ();
			transport_source.destroy ();

			_close (sctp_socket);
			sctp_socket = null;
		}

		public extern static void _close (void * sock);

		public void shutdown (SctpShutdownType type) throws IOError {
			_shutdown (sctp_socket, type);
		}

		public extern static void _shutdown (void * sock, SctpShutdownType type) throws IOError;

		public ssize_t recv (uint8[] buffer) throws IOError {
			ssize_t n = -1;

			try {
				uint16 stream_id;
				PayloadProtocolId protocol_id;
				SctpMessageFlags msg_flags;

				n = _recv (sctp_socket, buffer, out stream_id, out protocol_id, out msg_flags);

				if (protocol_id == WEBRTC_DCEP) {
					dcep_message.append (buffer[0:n]);
					if ((msg_flags & SctpMessageFlags.END_OF_RECORD) != 0) {
						handle_dcep_message (stream_id, dcep_message.steal ());
					}
					throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
				} else if (protocol_id == NONE || _state != OPENED) {
					throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
				}
			} finally {
				update_sctp_events ();
			}

			return n;
		}

		public ssize_t send (uint8[] buffer) throws IOError {
			if (_state != OPENED)
				throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");

			ssize_t n = ssize_t.min (buffer.length, (ssize_t) max_message_size);

			try {
				return _send (sctp_socket, stream_id, WEBRTC_BINARY, buffer[0:n]);
			} finally {
				update_sctp_events ();
			}
		}

		public void register_source (Source source, IOCondition condition) {
			lock (state)
				sources[source] = condition | IOCondition.ERR | IOCondition.HUP;
		}

		public void unregister_source (Source source) {
			lock (state)
				sources.unset (source);
		}

		private bool on_transport_socket_readable (DatagramBased datagram_based, IOCondition condition) {
			var v = InputVector ();
			v.buffer = transport_buffer;
			v.size = transport_buffer.length;

			InputVector[] vectors = { v };

			var m = InputMessage ();
			m.vectors = vectors;
			m.num_vectors = vectors.length;

			InputMessage[] messages = { m };

			try {
				transport_socket.receive_messages (messages, 0, 0, io_cancellable);

				unowned uint8[] data = (uint8[]) v.buffer;
				data.length = (int) messages[0].bytes_received;

				_handle_transport_packet (data);
			} catch (GLib.Error e) {
				return Source.REMOVE;
			}

			return Source.CONTINUE;
		}

		protected extern void _handle_transport_packet (uint8[] data);

		protected int _emit_transport_packet (uint8[] data) {
			try {
				Udp.send (data, transport_socket, io_cancellable);
				return 0;
			} catch (GLib.Error e) {
				return -1;
			}
		}

		protected void _on_sctp_socket_events_changed () {
			update_sctp_events ();

			if (_state == CREATED && setup == ACTIVE && (sctp_events & IOCondition.OUT) != 0) {
				stream_id = 1;

				uint8[] open_message = {
					DcepMessageType.DATA_CHANNEL_OPEN,
					/* Channel Type: DATA_CHANNEL_RELIABLE */ 0x00,
					/* Priority */ 0x00, 0x00,
					/* Reliability */ 0x00, 0x00, 0x00, 0x00,
					/* Label Length */ 0x00, 0x07,
					/* Protocol Length */ 0x00, 0x00,
					/* Label: "session" */ 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e
				};
				try {
					_send (sctp_socket, stream_id, WEBRTC_DCEP, open_message);
					_state = OPENING;
				} catch (IOError e) {
				}
			}
		}

		private void update_sctp_events () {
			IOCondition new_events = _query_sctp_socket_events (sctp_socket);

			lock (state) {
				sctp_events = new_events;

				foreach (var entry in sources.entries) {
					unowned Source source = entry.key;
					IOCondition c = entry.value;
					if ((new_events & c) != 0)
						source.set_ready_time (0);
				}

				sctp_source.invalidate ();
			}
		}

		protected extern static IOCondition _query_sctp_socket_events (void * sock);

		protected extern static ssize_t _recv (void * sock, uint8[] buffer, out uint16 stream_id,
			out PayloadProtocolId protocol_id, out SctpMessageFlags message_flags) throws IOError;

		protected extern static ssize_t _send (void * sock, uint16 stream_id, PayloadProtocolId protocol_id,
			uint8[] data) throws IOError;

		private void handle_dcep_message (uint16 stream_id, uint8[] message) throws IOError {
			DcepMessageType type = (DcepMessageType) message[0];

			switch (type) {
				case DATA_CHANNEL_OPEN: {
					if (_state != CREATED || setup == ACTIVE)
						return;

					this.stream_id = stream_id;

					uint8[] reply = { DcepMessageType.DATA_CHANNEL_ACK };
					_send (sctp_socket, stream_id, WEBRTC_DCEP, reply);

					_state = OPENED;

					break;
				}
				case DATA_CHANNEL_ACK:
					if (_state != OPENING)
						return;

					_state = OPENED;

					break;
			}
		}
	}

	protected enum SctpShutdownType {
		READ = 1,
		WRITE,
		READ_WRITE
	}

	[Flags]
	protected enum SctpMessageFlags {
		END_OF_RECORD,
		NOTIFICATION,
	}

	protected enum PayloadProtocolId {
		NONE = 0,
		WEBRTC_DCEP = 50,
		WEBRTC_STRING,
		WEBRTC_BINARY_PARTIAL,
		WEBRTC_BINARY,
		WEBRTC_STRING_PARTIAL,
		WEBRTC_STRING_EMPTY,
		WEBRTC_BINARY_EMPTY
	}

	protected enum DcepMessageType {
		DATA_CHANNEL_OPEN = 0x03,
		DATA_CHANNEL_ACK = 0x02
	}

	private class SctpInputStream : InputStream, PollableInputStream {
		public weak SctpConnection connection {
			get;
			construct;
		}

		public SctpInputStream (SctpConnection connection) {
			Object (connection: connection);
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			connection.shutdown (READ);
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override ssize_t read (uint8[] buffer, Cancellable? cancellable) throws IOError {
			assert_not_reached ();
		}

		public bool can_poll () {
			return true;
		}

		public bool is_readable () {
			return (connection.pending_io & IOCondition.IN) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new SctpIOSource (connection, IOCondition.IN), cancellable);
		}

		public ssize_t read_nonblocking_fn (uint8[] buffer) throws GLib.Error {
			return connection.recv (buffer);
		}
	}

	private class SctpOutputStream : OutputStream, PollableOutputStream {
		public weak SctpConnection connection {
			get;
			construct;
		}

		public SctpOutputStream (SctpConnection connection) {
			Object (connection: connection);
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			connection.shutdown (WRITE);
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override bool flush (GLib.Cancellable? cancellable) throws GLib.Error {
			return true;
		}

		public override async bool flush_async (int io_priority, GLib.Cancellable? cancellable) throws GLib.Error {
			return true;
		}

		public override ssize_t write (uint8[] buffer, Cancellable? cancellable) throws IOError {
			assert_not_reached ();
		}

		public bool can_poll () {
			return true;
		}

		public bool is_writable () {
			return (connection.pending_io & IOCondition.OUT) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new SctpIOSource (connection, IOCondition.OUT), cancellable);
		}

		public ssize_t write_nonblocking_fn (uint8[]? buffer) throws GLib.Error {
			return connection.send (buffer);
		}

		public PollableReturn writev_nonblocking_fn (OutputVector[] vectors, out size_t bytes_written) throws GLib.Error {
			assert_not_reached ();
		}
	}

	private class SctpIOSource : Source {
		public SctpConnection connection;
		public IOCondition condition;

		public SctpIOSource (SctpConnection connection, IOCondition condition) {
			this.connection = connection;
			this.condition = condition;

			connection.register_source (this, condition);
		}

		~SctpIOSource () {
			connection.unregister_source (this);
		}

		protected override bool prepare (out int timeout) {
			timeout = -1;
			return (connection.pending_io & condition) != 0;
		}

		protected override bool check () {
			return (connection.pending_io & condition) != 0;
		}

		protected override bool dispatch (SourceFunc? callback) {
			set_ready_time (-1);

			if (callback == null)
				return Source.REMOVE;

			return callback ();
		}

		protected static bool closure_callback (Closure closure) {
			var return_value = Value (typeof (bool));

			closure.invoke (ref return_value, {});

			return return_value.get_boolean ();
		}
	}

	private class SctpTimerSource : Source {
		private static int64 last_process_time = -1;

		public void invalidate () {
			set_ready_time (0);
		}

		protected override bool prepare (out int timeout) {
			return update_timer_status (out timeout);
		}

		protected override bool check () {
			return update_timer_status ();
		}

		private bool update_timer_status (out int timeout = null) {
			int64 now = get_monotonic_time ();

			if (last_process_time == -1)
				last_process_time = now;

			int next_timeout = _get_timeout ();
			if (next_timeout == -1) {
				last_process_time = -1;
				timeout = -1;
				return false;
			}

			int64 next_wakeup_time = last_process_time + next_timeout;

			bool ready = now >= next_wakeup_time;

			timeout = (int) int64.max (next_wakeup_time - now, 0);

			return ready;
		}

		protected override bool dispatch (SourceFunc? callback) {
			set_ready_time (-1);

			bool result = Source.CONTINUE;

			int64 now = get_monotonic_time ();
			int64 elapsed_usec = now - last_process_time;
			uint32 elapsed_msec = (uint32) (elapsed_usec / 1000);

			_process_timers (elapsed_msec);

			last_process_time = now;

			if (callback != null)
				result = callback ();

			return result;
		}

		protected extern static int _get_timeout ();
		protected extern static void _process_timers (uint32 elapsed_msec);
	}

	public async void generate_certificate (out uint8[] cert_der, out string cert_pem, out string key_pem) {
		var caller_context = MainContext.ref_thread_default ();

		Bytes? result_cert_der = null;
		string? result_cert_pem = null;
		string? result_key_pem = null;

		new Thread<bool> ("frida-generate-certificate", () => {
			uint8[] local_cert_der;
			string local_cert_pem;
			string local_key_pem;
			_generate_certificate (out local_cert_der, out local_cert_pem, out local_key_pem);

			result_cert_der = new Bytes.take ((owned) local_cert_der);
			result_cert_pem = (owned) local_cert_pem;
			result_key_pem = (owned) local_key_pem;

			var idle_source = new IdleSource ();
			idle_source.set_callback (generate_certificate.callback);
			idle_source.attach (caller_context);

			return true;
		});

		yield;

		cert_der = Bytes.unref_to_data ((owned) result_cert_der);
		cert_pem = (owned) result_cert_pem;
		key_pem = (owned) result_key_pem;
	}

	public extern void _generate_certificate (out uint8[] cert_der, out string cert_pem, out string key_pem);
}
#endif
```