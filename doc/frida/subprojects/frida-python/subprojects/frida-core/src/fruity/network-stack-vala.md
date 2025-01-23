Response:
### 功能概述

`network-stack.vala` 文件是 Frida 工具中用于处理网络栈的核心代码，主要实现了 TCP 和 UDP 网络通信的功能。它定义了一个 `NetworkStack` 接口，并提供了两个实现类：`SystemNetworkStack` 和 `VirtualNetworkStack`。这些类负责处理网络连接、数据传输、以及底层网络栈的管理。

#### 主要功能：
1. **TCP 连接管理**：
   - 提供了异步的 TCP 连接建立功能，支持超时和取消操作。
   - 实现了 TCP 连接的读写操作，支持非阻塞 I/O。

2. **UDP 套接字管理**：
   - 提供了 UDP 套接字的创建、绑定、连接和数据传输功能。
   - 支持 UDP 数据报的接收和发送。

3. **虚拟网络栈**：
   - 实现了基于 LWIP（轻量级 IP 协议栈）的虚拟网络栈，支持 IPv6 地址管理、数据报的发送和接收。
   - 提供了虚拟网络栈的启动、停止和数据传输功能。

4. **错误处理**：
   - 提供了详细的错误处理机制，包括连接超时、服务器未运行、传输错误等。

### 二进制底层与 Linux 内核

该文件主要涉及网络栈的实现，虽然不直接涉及 Linux 内核的修改，但它依赖于底层的网络协议栈（如 LWIP）来处理网络数据包。LWIP 是一个轻量级的 TCP/IP 协议栈，常用于嵌入式系统中。通过 LWIP，Frida 可以在用户空间实现网络通信，而不需要直接操作内核。

#### 举例说明：
- **TCP 连接的建立**：在 `SystemNetworkStack` 类中，`open_tcp_connection` 方法通过 `SocketClient` 类与远程服务器建立 TCP 连接。这个过程涉及到底层的 `socket` 系统调用，最终由内核处理。
- **UDP 数据报的发送**：在 `VirtualNetworkStack` 类中，`handle_incoming_datagram` 方法通过 LWIP 的 `PacketBuffer` 处理接收到的 UDP 数据报，并将其传递给上层应用。

### LLDB 调试示例

假设我们想要调试 `open_tcp_connection` 方法的执行过程，可以使用 LLDB 来设置断点并观察变量的值。

#### LLDB 指令示例：
```bash
# 启动 LLDB 并附加到 Frida 进程
lldb frida

# 设置断点在 `open_tcp_connection` 方法
b frida::fruity::SystemNetworkStack::open_tcp_connection

# 运行程序
run

# 当断点触发时，打印相关变量
p address
p cancellable

# 继续执行程序
continue
```

#### LLDB Python 脚本示例：
```python
import lldb

def set_breakpoint(debugger, module, function):
    target = debugger.GetSelectedTarget()
    breakpoint = target.BreakpointCreateByName(function, module)
    print(f"Breakpoint set at {function} in {module}")

def print_variables(frame):
    address = frame.FindVariable("address")
    cancellable = frame.FindVariable("cancellable")
    print(f"Address: {address}")
    print(f"Cancellable: {cancellable}")

def main():
    debugger = lldb.SBDebugger.Create()
    target = debugger.CreateTarget("frida")
    process = target.LaunchSimple(None, None, None)

    set_breakpoint(debugger, "frida::fruity::SystemNetworkStack", "open_tcp_connection")

    while process.GetState() == lldb.eStateStopped:
        for thread in process:
            if thread.GetStopReason() == lldb.eStopReasonBreakpoint:
                frame = thread.GetFrameAtIndex(0)
                print_variables(frame)
                process.Continue()

if __name__ == "__main__":
    main()
```

### 逻辑推理与输入输出

#### 假设输入与输出：
- **输入**：调用 `open_tcp_connection` 方法，传入一个 `InetSocketAddress` 对象和一个 `Cancellable` 对象。
- **输出**：如果连接成功，返回一个 `IOStream` 对象；如果连接失败，抛出 `Error` 或 `IOError` 异常。

#### 示例：
```vala
var address = new InetSocketAddress (new InetAddress.from_string ("127.0.0.1"), 8080);
var cancellable = new Cancellable ();

try {
    var stream = yield network_stack.open_tcp_connection (address, cancellable);
    // 使用 stream 进行数据传输
} catch (Error e) {
    print ("连接失败: %s\n", e.message);
}
```

### 用户常见错误

1. **未处理取消操作**：
   - 用户可能在调用 `open_tcp_connection` 时传入了一个 `Cancellable` 对象，但没有正确处理取消操作，导致程序在取消时无法正确释放资源。

2. **未处理超时**：
   - 用户可能没有设置超时时间，导致在网络不稳定的情况下，程序长时间等待连接。

3. **未正确处理异常**：
   - 用户可能没有捕获 `Error` 或 `IOError` 异常，导致程序在遇到网络错误时崩溃。

### 用户操作路径

1. **启动 Frida**：用户启动 Frida 工具，并加载目标应用程序。
2. **调用网络栈功能**：用户通过 Frida 的 API 调用 `open_tcp_connection` 或 `create_udp_socket` 方法。
3. **处理网络数据**：用户通过返回的 `IOStream` 或 `UdpSocket` 对象进行数据传输。
4. **调试与错误处理**：如果遇到问题，用户可以通过调试工具（如 LLDB）设置断点，观察变量的值，并处理异常。

### 总结

`network-stack.vala` 文件实现了 Frida 工具中的网络栈功能，支持 TCP 和 UDP 通信。通过 LLDB 调试工具，用户可以深入分析网络连接的建立过程，并处理常见的用户错误。该文件的设计充分考虑了异步操作、错误处理和资源管理，确保了网络通信的稳定性和可靠性。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/network-stack.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```
[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public interface NetworkStack : Object {
		public abstract InetAddress listener_ip {
			get;
		}

		public abstract uint scope_id {
			get;
		}

		public abstract async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable)
			throws Error, IOError;

		public async IOStream open_tcp_connection_with_timeout (InetSocketAddress address, uint timeout, Cancellable? cancellable)
				throws Error, IOError {
			bool timed_out = false;
			var open_cancellable = new Cancellable ();

			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource (timeout);
			timeout_source.set_callback (() => {
				timed_out = true;
				open_cancellable.cancel ();
				return Source.REMOVE;
			});
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				open_cancellable.cancel ();
				return Source.REMOVE;
			});
			cancel_source.attach (main_context);

			try {
				return yield open_tcp_connection (address, open_cancellable);
			} catch (IOError e) {
				assert (e is IOError.CANCELLED);
				if (timed_out)
					throw new Error.TIMED_OUT ("Networked Apple device is not responding");
				throw e;
			} finally {
				timeout_source.destroy ();
				cancel_source.destroy ();
			}
		}

		public abstract UdpSocket create_udp_socket () throws Error;
	}

	public interface UdpSocket : Object {
		public abstract DatagramBased datagram_based {
			get;
		}

		public abstract void bind (InetSocketAddress address) throws Error;
		public abstract InetSocketAddress get_local_address () throws Error;
		public abstract void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error;
	}

	public sealed class SystemNetworkStack : Object, NetworkStack {
		public InetAddress listener_ip {
			get {
				return _listener_ip;
			}
		}

		public uint scope_id {
			get {
				return _scope_id;
			}
		}

		private InetAddress _listener_ip;
		private uint _scope_id;

		public SystemNetworkStack (InetAddress listener_ip, uint scope_id) {
			_listener_ip = listener_ip;
			_scope_id = scope_id;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable) throws Error, IOError {
			SocketConnection connection;
			try {
				var client = new SocketClient ();
				connection = yield client.connect_async (address, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CONNECTION_REFUSED)
					throw new Error.SERVER_NOT_RUNNING ("%s", e.message);
				throw new Error.TRANSPORT ("%s", e.message);
			}

			Tcp.enable_nodelay (connection.socket);

			return connection;
		}

		public UdpSocket create_udp_socket () throws Error {
			try {
				var handle = new Socket (IPV6, DATAGRAM, UDP);
				return new SystemUdpSocket (handle);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private class SystemUdpSocket : Object, UdpSocket {
			public Socket handle {
				get;
				construct;
			}

			public DatagramBased datagram_based {
				get {
					return handle;
				}
			}

			public SystemUdpSocket (Socket handle) {
				Object (handle: handle);
			}

			public void bind (InetSocketAddress address) throws Error {
				try {
					handle.bind (address, true);
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public InetSocketAddress get_local_address () throws Error {
				try {
					return (InetSocketAddress) handle.get_local_address ();
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error {
				try {
					handle.connect (address, cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}
			}
		}
	}

	public sealed class VirtualNetworkStack : Object, NetworkStack {
		public signal void outgoing_datagram (Bytes datagram);

		public Bytes? ethernet_address {
			get;
			construct;
		}

		public InetAddress? ipv6_address {
			get;
			construct;
		}

		public InetAddress listener_ip {
			get {
				if (_cached_listener_ip == null)
					_cached_listener_ip = ip6_address_to_inet_address (raw_ipv6_address);
				return _cached_listener_ip;
			}
		}

		public uint scope_id {
			get {
				return raw_ipv6_address.zone;
			}
		}

		public uint16 mtu {
			get;
			construct;
		}

		private State state = STARTED;

		private Gee.Queue<Request> requests = new Gee.ArrayQueue<Request> ();
		private unowned Thread<bool>? lwip_thread;

		private LWIP.NetworkInterface handle;
		private LWIP.IP6Address raw_ipv6_address;
		private InetAddress? _cached_listener_ip;

		private MainContext main_context;

		private enum State {
			STARTED,
			STOPPED
		}

		public class VirtualNetworkStack (Bytes? ethernet_address, InetAddress? ipv6_address, uint16 mtu) {
			Object (
				ethernet_address: ethernet_address,
				ipv6_address: ipv6_address,
				mtu: mtu
			);
		}

		static construct {
			LWIP.Runtime.init (() => {});
		}

		construct {
			main_context = MainContext.ref_thread_default ();

			perform_on_lwip_thread (() => {
				LWIP.NetworkInterface.add_noaddr (ref handle, this, on_netif_init);
				handle.set_link_up ();
				handle.set_up ();
				return OK;
			});
			state = STARTED;
		}

		private static LWIP.ErrorCode on_netif_init (LWIP.NetworkInterface handle) {
			VirtualNetworkStack * self = handle.state;
			self->configure_netif (ref handle);
			return OK;
		}

		private void configure_netif (ref LWIP.NetworkInterface handle) {
			if (ethernet_address != null) {
				handle.output_ip6 = LWIP.Ethernet.IPv6.output;
				handle.linkoutput = on_netif_link_output;
			} else {
				handle.output_ip6 = on_netif_output_ip6;
			}

			handle.mtu = mtu;
			handle.flags = BROADCAST;

			if (ethernet_address != null) {
				assert (ethernet_address.length == LWIP.Ethernet.HWADDR_LEN);
				Memory.copy (&handle.hwaddr, ethernet_address.get_data (), LWIP.Ethernet.HWADDR_LEN);
				handle.hwaddr_len = LWIP.Ethernet.HWADDR_LEN;

				handle.flags |= ETHARP;
			}

			int8 chosen_index = 0;
			if (ipv6_address != null)
				handle.add_ip6_address (ip6_address_from_inet_address (ipv6_address), &chosen_index);
			else
				handle.create_ip6_linklocal_address (true);
			handle.ip6_addr_set_state (chosen_index, PREFERRED); // No need for conflict detection.
			raw_ipv6_address = handle.ip6_addr[chosen_index];
		}

		public override void dispose () {
			stop ();

			base.dispose ();
		}

		public void stop () {
			if (state == STOPPED)
				return;
			perform_on_lwip_thread (() => {
				handle.remove ();
				return OK;
			});
			state = STOPPED;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable = null)
				throws Error, IOError {
			check_started ();
			return yield TcpConnection.open (this, address, cancellable);
		}

		public UdpSocket create_udp_socket () throws Error {
			check_started ();
			return new Ipv6UdpSocket (this);
		}

		public void handle_incoming_datagram (Bytes datagram) throws Error {
			check_started ();

			check (perform_on_lwip_thread (() => {
				var pbuf = LWIP.PacketBuffer.alloc (RAW, (uint16) datagram.get_size (), POOL);
				pbuf.take (datagram.get_data ());

				var err = handle.input (pbuf, ref handle);
				if (err == OK)
					*((void **) &pbuf) = null;

				return err;
			}));
		}

		private static LWIP.ErrorCode on_netif_link_output (LWIP.NetworkInterface handle, LWIP.PacketBuffer pbuf) {
			VirtualNetworkStack * self = handle.state;
			self->emit_datagram (pbuf);
			return OK;
		}

		private static LWIP.ErrorCode on_netif_output_ip6 (LWIP.NetworkInterface handle, LWIP.PacketBuffer pbuf,
				LWIP.IP6Address address) {
			VirtualNetworkStack * self = handle.state;
			self->emit_datagram (pbuf);
			return OK;
		}

		private void emit_datagram (LWIP.PacketBuffer pbuf) {
			var buffer = new uint8[pbuf.tot_len];
			unowned uint8[] packet = pbuf.get_contiguous (buffer, pbuf.tot_len);
			var datagram = new Bytes (packet[:pbuf.tot_len]);

			schedule_on_frida_thread (() => {
				if (state == STARTED)
					outgoing_datagram (datagram);
				return Source.REMOVE;
			});
		}

		internal LWIP.ErrorCode perform_on_lwip_thread (owned WorkFunc work) {
			var req = new Request ((owned) work);

			if (Thread.self<bool> () == lwip_thread) {
				perform_request (req);
			} else {
				lock (requests)
					requests.offer (req);
				LWIP.Runtime.schedule (perform_next_request);
			}

			return req.join ();
		}

		private void perform_next_request () {
			if (lwip_thread == null)
				lwip_thread = Thread.self ();

			Request req;
			lock (requests)
				req = requests.poll ();

			perform_request (req);
		}

		private static void perform_request (Request req) {
			LWIP.ErrorCode err = req.work ();
			req.complete (err);
		}

		private void check_started () throws Error {
			if (state != STARTED)
				throw new Error.INVALID_OPERATION ("Networking stack has been stopped");
		}

		internal delegate LWIP.ErrorCode WorkFunc ();

		private class Request {
			public WorkFunc work;

			private bool completed = false;
			private LWIP.ErrorCode error;
			private Mutex mutex = Mutex ();
			private Cond cond = Cond ();

			public Request (owned WorkFunc work) {
				this.work = (owned) work;
			}

			public LWIP.ErrorCode join () {
				mutex.lock ();
				while (!completed)
					cond.wait (mutex);
				var err = error;
				mutex.unlock ();
				return err;
			}

			public void complete (LWIP.ErrorCode err) {
				mutex.lock ();
				completed = true;
				error = err;
				cond.signal ();
				mutex.unlock ();
			}
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private class TcpConnection : IOStream, AsyncInitable {
			public VirtualNetworkStack netstack {
				get;
				construct;
			}

			public InetSocketAddress address {
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
						return events;
				}
			}

			private Promise<bool> established = new Promise<bool> ();

			private State _state = OPENING;
			private TcpInputStream _input_stream;
			private TcpOutputStream _output_stream;

			private unowned LWIP.TcpPcb? pcb;
			private IOCondition events = 0;
			private ByteArray rx_buf = new ByteArray.sized (64 * 1024);
			private ByteArray tx_buf = new ByteArray.sized (64 * 1024);
			private size_t tx_space_available = 0;

			private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

			private MainContext main_context;

			public enum State {
				OPENING,
				OPENED,
				CLOSED
			}

			public static async TcpConnection open (VirtualNetworkStack netstack, InetSocketAddress address,
					Cancellable? cancellable) throws Error, IOError {
				var connection = new TcpConnection (netstack, address);

				try {
					yield connection.init_async (Priority.DEFAULT, cancellable);
				} catch (GLib.Error e) {
					throw_api_error (e);
				}

				return connection;
			}

			private TcpConnection (VirtualNetworkStack netstack, InetSocketAddress address) {
				Object (netstack: netstack, address: address);
			}

			construct {
				_input_stream = new TcpInputStream (this);
				_output_stream = new TcpOutputStream (this);

				main_context = MainContext.ref_thread_default ();
			}

			public override void dispose () {
				_output_stream.detach ();
				_input_stream.detach ();

				stop ();

				base.dispose ();
			}

			private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
				LWIP.Runtime.schedule (do_start);

				try {
					yield established.future.wait_async (cancellable);
				} catch (GLib.Error e) {
					stop ();
					throw_api_error (e);
				}

				return true;
			}

			private void do_start () {
				pcb = LWIP.TcpPcb.make (V6);
				pcb.set_user_data (this);
				pcb.set_recv_callback ((user_data, pcb, pbuf, err) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_recv ((owned) pbuf, err);
					return OK;
				});
				pcb.set_sent_callback ((user_data, pcb, len) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_sent (len);
					return OK;
				});
				pcb.set_error_callback ((user_data, err) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_error (err);
				});
				pcb.set_flags (TIMESTAMP | SACK);
				pcb.nagle_disable ();
				pcb.bind_netif (&netstack.handle);

				var err = pcb.connect (ip6_address_from_inet_socket_address (address), address.get_port (), (user_data, pcb, err) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_connect ();
					return OK;
				});
				if (err != OK) {
					schedule_on_frida_thread (() => {
						established.reject (parse_error (err));
						return Source.REMOVE;
					});
				}
			}

			private void stop () {
				netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;
					pcb.set_user_data (null);
					if (pcb.close () != OK)
						pcb.abort ();
					pcb = null;
					return OK;
				});

				_state = CLOSED;
				update_events ();
			}

			private void detach_from_pcb () {
				pcb.set_user_data (null);
				pcb = null;
			}

			private void on_connect () {
				lock (state)
					tx_space_available = pcb.query_available_send_buffer_space ();
				update_events ();

				schedule_on_frida_thread (() => {
					_state = OPENED;

					if (!established.future.ready)
						established.resolve (true);

					return Source.REMOVE;
				});
			}

			private void on_recv (owned LWIP.PacketBuffer? pbuf, LWIP.ErrorCode err) {
				if (pbuf == null) {
					detach_from_pcb ();
					schedule_on_frida_thread (() => {
						_state = CLOSED;
						update_events ();
						return Source.REMOVE;
					});
					return;
				}

				var buffer = new uint8[pbuf.tot_len];
				unowned uint8[] chunk = pbuf.get_contiguous (buffer, pbuf.tot_len);
				lock (state)
					rx_buf.append (chunk[:pbuf.tot_len]);
				update_events ();
			}

			private void on_sent (uint16 len) {
				lock (state)
					tx_space_available = pcb.query_available_send_buffer_space () - tx_buf.len;
				update_events ();
			}

			private void on_error (LWIP.ErrorCode err) {
				bool pcb_already_freed = err == ABRT;
				if (pcb_already_freed)
					pcb = null;
				else
					detach_from_pcb ();
				schedule_on_frida_thread (() => {
					_state = CLOSED;
					update_events ();

					if (!established.future.ready)
						established.reject (parse_error (err));

					return Source.REMOVE;
				});
			}

			public override bool close (GLib.Cancellable? cancellable) throws IOError {
				stop ();
				return true;
			}

			public override async bool close_async (int io_priority, GLib.Cancellable? cancellable) throws IOError {
				stop ();
				return true;
			}

			public void shutdown_rx () throws IOError {
				check_io (netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;
					return pcb.shutdown (true, false);
				}));
			}

			public void shutdown_tx () throws IOError {
				check_io (netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;
					return pcb.shutdown (false, true);
				}));
			}

			public ssize_t recv (uint8[] buffer) throws IOError {
				ssize_t n = 0;

				netstack.perform_on_lwip_thread (() => {
					lock (state) {
						n = ssize_t.min (buffer.length, rx_buf.len);
						if (n == 0)
							return OK;
						Memory.copy (buffer, rx_buf.data, n);
						rx_buf.remove_range (0, (uint) n);
					}

					if (pcb == null)
						return OK;

					size_t remainder = n;
					while (remainder != 0) {
						uint16 chunk = (uint16) size_t.min (remainder, uint16.MAX);
						pcb.notify_received (chunk);
						remainder -= chunk;
					}

					return OK;
				});

				if (n == 0) {
					if (_state == CLOSED)
						return 0;
					throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
				}

				update_events ();

				return n;
			}

			public ssize_t send (uint8[] buffer) throws IOError {
				ssize_t n = 0;

				netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;

					lock (state) {
						n = ssize_t.min (buffer.length, (ssize_t) tx_space_available);
						if (n == 0)
							return OK;
						tx_buf.append (buffer[:n]);
						tx_space_available -= n;
					}

					size_t available_space = pcb.query_available_send_buffer_space ();

					uint8[]? data = null;
					lock (state) {
						size_t num_bytes_to_write = size_t.min (tx_buf.len, available_space);
						if (num_bytes_to_write != 0) {
							data = tx_buf.data[:num_bytes_to_write];
							tx_buf.remove_range (0, (uint) num_bytes_to_write);
						}
					}
					if (data == null)
						return OK;

					pcb.write (data, COPY);
					pcb.output ();

					available_space = pcb.query_available_send_buffer_space ();
					lock (state)
						tx_space_available = available_space - tx_buf.len;

					return OK;
				});

				if (n == 0)
					throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");

				update_events ();

				return n;
			}

			public void register_source (Source source, IOCondition condition) {
				lock (state)
					sources[source] = condition | IOCondition.ERR | IOCondition.HUP;
			}

			public void unregister_source (Source source) {
				lock (state)
					sources.unset (source);
			}

			private void update_events () {
				lock (state) {
					IOCondition new_events = 0;

					if (rx_buf.len != 0 || _state == CLOSED)
						new_events |= IN;

					if (tx_space_available != 0)
						new_events |= OUT;

					events = new_events;

					foreach (var entry in sources.entries) {
						unowned Source source = entry.key;
						IOCondition c = entry.value;
						if ((new_events & c) != 0)
							source.set_ready_time (0);
					}
				}

				notify_property ("pending-io");
			}

			private void schedule_on_frida_thread (owned SourceFunc function) {
				var source = new IdleSource ();
				source.set_callback ((owned) function);
				source.attach (main_context);
			}
		}

		private class TcpInputStream : InputStream, PollableInputStream {
			private weak TcpConnection connection;

			public TcpInputStream (TcpConnection connection) {
				Object ();
				this.connection = connection;
			}

			internal void detach () {
				connection = null;
			}

			public override bool close (Cancellable? cancellable) throws IOError {
				if (connection != null)
					connection.shutdown_rx ();
				return true;
			}

			public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
				return close (cancellable);
			}

			public override ssize_t read (uint8[] buffer, Cancellable? cancellable) throws IOError {
				if (connection == null)
					return 0;

				if (!is_readable ()) {
					bool done = false;
					var mutex = Mutex ();
					var cond = Cond ();

					ulong io_handler = connection.notify["pending-io"].connect ((obj, pspec) => {
						if (is_readable ()) {
							mutex.lock ();
							done = true;
							cond.signal ();
							mutex.unlock ();
						}
					});
					ulong cancellation_handler = 0;
					if (cancellable != null) {
						cancellation_handler = cancellable.connect (() => {
							mutex.lock ();
							done = true;
							cond.signal ();
							mutex.unlock ();
						});
					}

					if (!is_readable ()) {
						mutex.lock ();
						while (!done)
							cond.wait (mutex);
						mutex.unlock ();
					}

					if (cancellation_handler != 0)
						cancellable.disconnect (cancellation_handler);
					connection.disconnect (io_handler);

					cancellable.set_error_if_cancelled ();
				}

				return connection.recv (buffer);
			}

			public bool can_poll () {
				return true;
			}

			public bool is_readable () {
				if (connection == null)
					return true;
				return (connection.pending_io & IOCondition.IN) != 0;
			}

			public PollableSource create_source (Cancellable? cancellable) {
				return new PollableSource.full (this, new TcpIOSource (connection, IOCondition.IN), cancellable);
			}

			public ssize_t read_nonblocking_fn (uint8[] buffer) throws GLib.Error {
				if (connection == null)
					return 0;
				return connection.recv (buffer);
			}
		}

		private class TcpOutputStream : OutputStream, PollableOutputStream {
			private weak TcpConnection? connection;

			public TcpOutputStream (TcpConnection connection) {
				Object ();
				this.connection = connection;
			}

			internal void detach () {
				connection = null;
			}

			public override bool close (Cancellable? cancellable) throws IOError {
				if (connection != null)
					connection.shutdown_tx ();
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
				if (connection == null)
					return false;
				return (connection.pending_io & IOCondition.OUT) != 0;
			}

			public PollableSource create_source (Cancellable? cancellable) {
				return new PollableSource.full (this, new TcpIOSource (connection, IOCondition.OUT), cancellable);
			}

			public ssize_t write_nonblocking_fn (uint8[]? buffer) throws GLib.Error {
				if (connection == null)
					throw new IOError.CLOSED ("Connection is closed");
				return connection.send (buffer);
			}

			public PollableReturn writev_nonblocking_fn (OutputVector[] vectors, out size_t bytes_written) throws GLib.Error {
				assert_not_reached ();
			}
		}

		private class TcpIOSource : Source {
			public TcpConnection connection;
			public IOCondition condition;

			public TcpIOSource (TcpConnection? connection, IOCondition condition) {
				this.connection = connection;
				this.condition = condition;

				if (connection != null)
					connection.register_source (this, condition);
			}

			~TcpIOSource () {
				if (connection != null)
					connection.unregister_source (this);
			}

			protected override bool prepare (out int timeout) {
				timeout = -1;
				return is_ready ();
			}

			protected override bool check () {
				return is_ready ();
			}

			private bool is_ready () {
				IOCondition pending_io = (connection != null) ? connection.pending_io : IOCondition.IN;
				return (pending_io & condition) != 0;
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

		private class Ipv6UdpSocket : Object, UdpSocket, DatagramBased {
			public VirtualNetworkStack netstack {
				get;
				construct;
			}

			public DatagramBased datagram_based {
				get {
					return this;
				}
			}

			public IOCondition pending_io {
				get {
					lock (events)
						return events;
				}
			}

			private unowned LWIP.UdpPcb? pcb;
			private IOCondition events = OUT;
			private Gee.Queue<Packet> rx_queue = new Gee.ArrayQueue<Packet> ();

			private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

			public Ipv6UdpSocket (VirtualNetworkStack netstack) {
				Object (netstack: netstack);
			}

			construct {
				netstack.perform_on_lwip_thread (() => {
					pcb = LWIP.UdpPcb.make (V6);
					pcb.set_recv_callback (on_recv);
					pcb.bind_netif (&netstack.handle);
					return OK;
				});
			}

			public override void dispose () {
				_netstack.perform_on_lwip_thread (() => {
					pcb.remove ();
					pcb = null;
					return OK;
				});

				base.dispose ();
			}

			private void on_recv (LWIP.UdpPcb pcb, owned LWIP.PacketBuffer? pbuf, LWIP.IP6Address addr, uint16 port) {
				var buffer = new uint8[pbuf.tot_len];
				unowned uint8[] chunk = pbuf.get_contiguous (buffer, pbuf.tot_len);

				var bytes = new Bytes (chunk[:pbuf.tot_len]);
				var sender = ip6_address_to_inet_socket_address (addr, port);
				var packet = new Packet (bytes, sender);

				lock (events)
					rx_queue.offer (packet);
				update_events ();
			}

			public void bind (InetSocketAddress address) throws Error {
				check (netstack.perform_on_lwip_thread (() => {
					return pcb.bind (ip6_address_from_inet_socket_address (address), address.get_port ());
				}));
			}

			public InetSocketAddress get_local_address () throws Error {
				InetSocketAddress? result = null;
				netstack.perform_on_lwip_thread (() => {
					result = ip6_address_to_inet_socket_address (pcb.local_ip, pcb.local_port);
					return OK;
				});
				return result;
			}

			public void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error {
				check (netstack.perform_on_lwip_thread (() => {
					return pcb.connect (ip6_address_from_inet_socket_address (address), address.get_port ());
				}));
			}

			public int datagram_receive_messages (InputMessage[] messages, int flags, int64 timeout,
					Cancellable? cancellable) throws GLib.Error {
				if (flags != 0)
					throw new IOError.NOT_SUPPORTED ("Flags not supported");
				if (timeout != 0)
					throw new IOError.NOT_SUPPORTED ("Blocking I/O not supported");

				int received;
				for (received = 0; received != messages.length; received++) {
					Packet? packet;
					lock (events)
						packet = rx_queue.poll ();
					if (packet == null) {
						if (received == 0)
							throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
						break;
					}
					update_events ();

					if (messages[received].address != null)
						*messages[received].address = packet.address.ref ();

					messages[received].bytes_received = 0;
					messages[received].flags = 0;

					var bytes = packet.bytes;
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
				}

				return received;
			}

			public virtual int datagram_send_messages (OutputMessage[] messages, int flags, int64 timeout,
					Cancellable? cancellable) throws GLib.Error {
				if (flags != 0)
					throw new IOError.NOT_SUPPORTED ("Flags not supported");

				var packets = new Gee.ArrayList<Packet> ();
				foreach (unowned OutputMessage message in messages) {
					var bytes = new ByteArray ();
					foreach (unowned OutputVector vector in message.vectors) {
						unowned uint8[] data = (uint8[]) vector.buffer;
						bytes.append (data[:vector.size]);
					}
					packets.add (
						new Packet (ByteArray.free_to_bytes ((owned) bytes), (InetSocketAddress) message.address));
				}

				int sent = 0;
				var err = netstack.perform_on_lwip_thread (() => {
					LWIP.ErrorCode err = OK;
					foreach (var packet in packets) {
						var pbuf = LWIP.PacketBuffer.alloc (RAW, (uint16) packet.bytes.get_size (), POOL);
						pbuf.take (packet.bytes.get_data ());

						InetSocketAddress? dst_addr = packet.address;
						if (dst_addr != null)
							err = pcb.sendto (pbuf, ip6_address_from_inet_socket_address (dst_addr), dst_addr.get_port ());
						else
							err = pcb.send (pbuf);
						if (err == OK)
							sent++;
						else
							break;
					}
					return err;
				});
				if (sent == 0)
					check_io (err);
				return sent;
			}

			public virtual DatagramBasedSource datagram_create_source (IOCondition condition, Cancellable? cancellable) {
				return new Ipv6UdpSocketSource (this, condition);
			}

			public virtual IOCondition datagram_condition_check (IOCondition condition) {
				assert_not_reached ();
			}

			public virtual bool datagram_condition_wait (IOCondition condition, int64 timeout, Cancellable? cancellable)
					throws GLib.Error {
				assert_not_reached ();
			}

			public void register_source (Source source, IOCondition condition) {
				lock (events)
					sources[source] = condition | IOCondition.ERR | IOCondition.HUP;
			}

			public void unregister_source (Source source) {
				lock (events)
					sources.unset (source);
			}

			private void update_events () {
				lock (events) {
					IOCondition new_events = OUT;

					if (!rx_queue.is_empty)
						new_events |= IN;

					events = new_events;

					foreach (var entry in sources.entries) {
						unowned Source source = entry.key;
						IOCondition c = entry.value;
						if ((new_events & c) != 0)
							source.set_ready_time (0);
					}
				}

				notify_property ("pending-io");
			}

			private class Packet {
				public Bytes bytes;
				public InetSocketAddress? address;

				public Packet (Bytes bytes, InetSocketAddress? address) {
					this.bytes = bytes;
					this.address = address;
				}
			}
		}

		private class Ipv6UdpSocketSource : DatagramBasedSource {
			public Ipv6UdpSocket socket;
			public IOCondition condition;

			public Ipv6UdpSocketSource (Ipv6UdpSocket socket, IOCondition condition) {
				this.socket = socket;
				this.condition = condition;

				socket.register_source (this, condition);
			}

			~Ipv6UdpSocketSource () {
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

		private static void check (LWIP.ErrorCode err) throws Error {
			if (err != OK)
				throw parse_error (err);
		}

		private static void check_io (LWIP.ErrorCode err) throws IOError {
			if (err != OK)
				throw IOError.from_errno (err.to_errno ());
		}

		private static Error parse_error (LWIP.ErrorCode err) {
			unowned string message = strerror (err.to_errno ());
			if (err == RST)
				return new Error.SERVER_NOT_RUNNING ("%s", message);
			return new Error.TRANSPORT ("%s", message);
		}

		private static LWIP.IP6Address ip6_address_from_inet_socket_address (InetSocketAddress address) {
			var addr = ip6_address_from_inet_address (address.get_address ());
			addr.zone = (uint8) address.scope_id;
			return addr;
		}

		private static LWIP.IP6Address ip6_address_from_inet_address (InetAddress address) {
			return LWIP.IP6Address.parse (address.to_string ());
		}

		private static InetSocketAddress ip6_address_to_inet_socket_address (LWIP.IP6Address address, uint16 port) {
			return (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: ip6_address_to_inet_address (address),
				port: port,
				scope_id: address.zone
			);
		}

		private static InetAddress ip6_address_to_inet_address (LWIP.IP6Address address) {
			char buf[40];
			return new InetAddress.from_string (address.to_string (buf));
		}
	}
}
```