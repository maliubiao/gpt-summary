Response:
### 功能归纳

该文件是Frida工具中用于处理QUIC（Quick UDP Internet Connections）协议的核心部分，主要负责建立和管理QUIC隧道连接。以下是该文件的主要功能：

1. **QUIC隧道连接的建立与管理**：
   - 通过`QuicTunnelConnection`类，实现了QUIC协议的客户端连接。它负责初始化QUIC连接、处理数据流、管理加密和认证等。
   - 使用`NGTcp2`库来处理QUIC协议的低层细节，包括数据包的发送与接收、流的控制、加密解密等。

2. **加密与认证**：
   - 使用OpenSSL库进行TLS加密和认证。`ssl_ctx`和`ssl`对象用于配置TLS客户端上下文，并使用本地密钥对和远程公钥进行认证。
   - 通过`make_certificate`函数生成自签名证书，用于QUIC连接的TLS握手。

3. **数据流管理**：
   - 通过`Stream`类管理QUIC连接中的数据流。每个流都有一个唯一的ID，并且可以发送和接收数据。
   - `on_recv_stream_data`和`on_recv_datagram`回调函数用于处理接收到的流数据和数据报。

4. **网络栈的虚拟化**：
   - 使用`VirtualNetworkStack`类来虚拟化网络栈，处理隧道的网络数据包。`_tunnel_netstack`对象负责处理隧道的入站和出站数据报。

5. **异步操作与事件循环**：
   - 使用GLib的异步操作和事件循环机制来处理QUIC连接的异步初始化、数据发送与接收等操作。
   - `process_pending_writes`函数用于处理待发送的数据包，确保数据能够及时发送。

6. **错误处理与连接关闭**：
   - 通过`perform_teardown`函数处理连接的关闭操作，释放资源并通知相关方连接已关闭。
   - 在连接关闭时，会发送`CONNECTION_CLOSE`帧通知对端。

### 二进制底层与Linux内核

该文件主要涉及网络协议栈的实现，特别是QUIC协议的实现。虽然它不直接涉及Linux内核，但它依赖于底层的网络栈和加密库（如OpenSSL）来处理数据包的发送与接收、加密解密等操作。

- **OpenSSL**：用于TLS加密和认证，处理QUIC协议中的加密握手和数据加密。
- **NGTcp2**：一个用于处理QUIC协议的低层库，负责数据包的发送与接收、流的控制、加密解密等。

### LLDB调试示例

假设你想调试`QuicTunnelConnection`类的`init_async`方法，可以使用以下LLDB命令或Python脚本来设置断点并观察变量的值：

#### LLDB命令示例

```bash
# 设置断点
b frida::subprojects::frida-core::src::fruity::xpc::QuicTunnelConnection::init_async

# 运行程序
run

# 当断点命中时，打印变量值
p local_keypair
p remote_pubkey
p socket

# 继续执行
continue
```

#### LLDB Python脚本示例

```python
import lldb

def quic_tunnel_init_async(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 设置断点
    breakpoint = target.BreakpointCreateByName("frida::subprojects::frida-core::src::fruity::xpc::QuicTunnelConnection::init_async")
    print(f"Breakpoint set at {breakpoint.GetNumLocations()} locations")

    # 运行程序
    process.Continue()

    # 当断点命中时，打印变量值
    local_keypair = frame.FindVariable("local_keypair")
    remote_pubkey = frame.FindVariable("remote_pubkey")
    socket = frame.FindVariable("socket")

    print(f"local_keypair: {local_keypair}")
    print(f"remote_pubkey: {remote_pubkey}")
    print(f"socket: {socket}")

    # 继续执行
    process.Continue()

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f quic_tunnel_init_async quic_tunnel_init_async')
```

### 假设输入与输出

假设输入是一个QUIC连接的初始化请求，包含本地密钥对和远程公钥。输出是一个已建立的QUIC连接对象。

- **输入**：
  - `local_keypair`：本地密钥对，用于TLS握手。
  - `remote_pubkey`：远程公钥，用于验证远程服务器的身份。
  - `address`：远程服务器的地址。

- **输出**：
  - `connection`：一个已建立的QUIC连接对象，可以用于发送和接收数据。

### 常见使用错误

1. **密钥对不匹配**：
   - 如果本地密钥对与远程公钥不匹配，TLS握手将失败，导致连接无法建立。
   - 示例错误：`OpenSSL.SSL.Error: SSL handshake failed`

2. **网络不可达**：
   - 如果远程服务器地址不可达，UDP连接将失败。
   - 示例错误：`GLib.IOError: Network is unreachable`

3. **数据包丢失**：
   - 由于QUIC基于UDP，数据包可能会丢失。如果丢失的数据包是关键的控制信息（如握手数据包），连接将失败。
   - 示例错误：`NGTcp2.ErrorCode: Connection timed out`

### 用户操作步骤

1. **初始化QUIC连接**：
   - 用户调用`QuicTunnelConnection`的构造函数，传入本地密钥对、远程公钥和服务器地址。
   - 用户调用`init_async`方法，开始异步初始化QUIC连接。

2. **处理数据流**：
   - 用户通过`Stream`类发送和接收数据。
   - 用户可以通过`on_recv_stream_data`和`on_recv_datagram`回调函数处理接收到的数据。

3. **关闭连接**：
   - 用户调用`close`方法，关闭QUIC连接并释放资源。

### 调试线索

1. **连接初始化失败**：
   - 检查`local_keypair`和`remote_pubkey`是否正确。
   - 检查网络连接是否正常，确保远程服务器地址可达。

2. **数据流异常**：
   - 检查`on_recv_stream_data`和`on_recv_datagram`回调函数，确保数据处理逻辑正确。
   - 检查`Stream`类的`send`和`on_recv`方法，确保数据发送和接收逻辑正确。

3. **连接关闭异常**：
   - 检查`perform_teardown`方法，确保资源释放逻辑正确。
   - 检查`close`方法的调用时机，确保连接在不再需要时被正确关闭。

通过以上步骤和调试线索，用户可以逐步排查和解决QUIC连接中的问题。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/xpc.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
ack, local_keypair, remote_pubkey);

			try {
				yield connection.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return connection;
		}

		private QuicTunnelConnection (InetSocketAddress address, NetworkStack netstack, TunnelKey local_keypair,
				TunnelKey remote_pubkey) {
			Object (
				address: address,
				netstack: netstack,
				local_keypair: local_keypair,
				remote_pubkey: remote_pubkey
			);
		}

		construct {
			connection_ref.get_conn = conn_ref => {
				QuicTunnelConnection * self = conn_ref.user_data;
				return self->connection;
			};
			connection_ref.user_data = this;

			ssl_ctx = new OpenSSL.SSLContext (OpenSSL.SSLMethod.tls_client ());
			NGTcp2.Crypto.Quictls.configure_client_context (ssl_ctx);
			ssl_ctx.use_certificate (make_certificate (local_keypair.handle));
			ssl_ctx.use_private_key (local_keypair.handle);

			ssl = new OpenSSL.SSL (ssl_ctx);
			ssl.set_app_data (&connection_ref);
			ssl.set_connect_state ();
			ssl.set_alpn_protos (ALPN.data);
			ssl.set_quic_transport_version (OpenSSL.TLSExtensionType.quic_transport_parameters);

			main_context = MainContext.ref_thread_default ();
		}

		public override void dispose () {
			perform_teardown ();

			base.dispose ();
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			socket = netstack.create_udp_socket ();
			socket.bind ((InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: netstack.listener_ip,
				scope_id: netstack.scope_id
			));
			socket.socket_connect (address, cancellable);

			raw_local_address = address_to_native (socket.get_local_address ());
			uint8[] raw_remote_address = address_to_native (address);

			var dcid = make_connection_id (NGTcp2.MIN_INITIAL_DCIDLEN);
			var scid = make_connection_id (NGTcp2.MIN_INITIAL_DCIDLEN);

			var path = NGTcp2.Path () {
				local = NGTcp2.Address () { addr = raw_local_address },
				remote = NGTcp2.Address () { addr = raw_remote_address },
			};

			var callbacks = NGTcp2.Callbacks () {
				get_new_connection_id = on_get_new_connection_id,
				extend_max_local_streams_bidi = (conn, max_streams, user_data) => {
					QuicTunnelConnection * self = user_data;
					return self->on_extend_max_local_streams_bidi (max_streams);
				},
				stream_close = (conn, flags, stream_id, app_error_code, user_data, stream_user_data) => {
					QuicTunnelConnection * self = user_data;
					return self->on_stream_close (flags, stream_id, app_error_code);
				},
				recv_stream_data = (conn, flags, stream_id, offset, data, user_data, stream_user_data) => {
					QuicTunnelConnection * self = user_data;
					return self->on_recv_stream_data (flags, stream_id, offset, data);
				},
				recv_datagram = (conn, flags, data, user_data) => {
					QuicTunnelConnection * self = user_data;
					return self->on_recv_datagram (flags, data);
				},
				rand = on_rand,
				client_initial = NGTcp2.Crypto.client_initial_cb,
				recv_crypto_data = NGTcp2.Crypto.recv_crypto_data_cb,
				encrypt = NGTcp2.Crypto.encrypt_cb,
				decrypt = NGTcp2.Crypto.decrypt_cb,
				hp_mask = NGTcp2.Crypto.hp_mask_cb,
				recv_retry = NGTcp2.Crypto.recv_retry_cb,
				update_key = NGTcp2.Crypto.update_key_cb,
				delete_crypto_aead_ctx = NGTcp2.Crypto.delete_crypto_aead_ctx_cb,
				delete_crypto_cipher_ctx = NGTcp2.Crypto.delete_crypto_cipher_ctx_cb,
				get_path_challenge_data = NGTcp2.Crypto.get_path_challenge_data_cb,
				version_negotiation = NGTcp2.Crypto.version_negotiation_cb,
			};

			var settings = NGTcp2.Settings.make_default ();
			settings.initial_ts = make_timestamp ();
			settings.max_tx_udp_payload_size = MAX_UDP_PAYLOAD_SIZE;
			settings.no_tx_udp_payload_size_shaping = true;
			settings.handshake_timeout = 5ULL * NGTcp2.SECONDS;

			var transport_params = NGTcp2.TransportParams.make_default ();
			transport_params.max_datagram_frame_size = MAX_QUIC_DATAGRAM_SIZE;
			transport_params.max_idle_timeout = 30ULL * NGTcp2.SECONDS;
			transport_params.initial_max_data = 1048576;
			transport_params.initial_max_stream_data_bidi_local = 1048576;

			NGTcp2.Connection.make_client (out connection, dcid, scid, path, NGTcp2.ProtocolVersion.V1, callbacks,
				settings, transport_params, null, this);
			connection.set_tls_native_handle (ssl);
			connection.set_keep_alive_timeout (KEEP_ALIVE_TIMEOUT);

			rx_source = socket.datagram_based.create_source (IOCondition.IN, io_cancellable);
			rx_source.set_callback (on_socket_readable);
			rx_source.attach (main_context);

			process_pending_writes ();

			yield establish_request.future.wait_async (cancellable);

			return true;
		}

		private void on_control_stream_opened () {
			var zeroed_padding_packet = new uint8[PREFERRED_MTU];
			send_datagram (new Bytes.take ((owned) zeroed_padding_packet));

			control_stream.send (make_handshake_request (PREFERRED_MTU).get_data ());
		}

		private void on_control_stream_response (string json) throws Error {
			tunnel_params = TunnelParameters.from_json (new JsonObjectReader (json));

			_tunnel_netstack = new VirtualNetworkStack (null, tunnel_params.address, tunnel_params.mtu);
			_tunnel_netstack.outgoing_datagram.connect (send_datagram);

			establish_request.resolve (true);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (connection == null)
				return;

			state = CLOSE_SCHEDULED;
			process_pending_writes ();

			try {
				yield close_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private void perform_teardown () {
			if (close_request.future.ready)
				return;

			connection = null;
			socket = null;

			io_cancellable.cancel ();

			if (rx_source != null) {
				rx_source.destroy ();
				rx_source = null;
			}

			if (write_idle != null) {
				write_idle.destroy ();
				write_idle = null;
			}

			if (expiry_timer != null) {
				expiry_timer.destroy ();
				expiry_timer = null;
			}

			if (_tunnel_netstack != null)
				_tunnel_netstack.stop ();

			close_request.resolve (true);

			closed ();
		}

		private void on_stream_data_available (Stream stream, uint8[] data, out size_t consumed) {
			if (stream != control_stream || establish_request.future.ready) {
				consumed = data.length;
				return;
			}

			consumed = 0;

			if (data.length < 12)
				return;

			var buf = new Buffer (new Bytes.static (data), BIG_ENDIAN);

			try {
				string magic = buf.read_fixed_string (0, 8);
				if (magic != "CDTunnel")
					throw new Error.PROTOCOL ("Invalid magic");

				size_t body_size = buf.read_uint16 (8);
				size_t body_available = data.length - 10;
				if (body_available < body_size)
					return;

				var raw_json = new uint8[body_size + 1];
				Memory.copy (raw_json, data + 10, body_size);

				unowned string json = (string) raw_json;
				if (!json.validate ())
					throw new Error.PROTOCOL ("Invalid UTF-8");

				on_control_stream_response (json);

				consumed = 10 + body_size;
			} catch (Error e) {
				if (!establish_request.future.ready)
					establish_request.reject (e);
			}
		}

		private void send_datagram (Bytes datagram) {
			tx_datagrams.offer (datagram);
			process_pending_writes ();
		}

		private bool on_socket_readable (DatagramBased datagram_based, IOCondition condition) {
			try {
				InetSocketAddress remote_address;
				size_t n = Udp.recv (rx_buf, socket.datagram_based, io_cancellable, out remote_address);

				uint8[] raw_remote_address = address_to_native (remote_address);

				var path = NGTcp2.Path () {
					local = NGTcp2.Address () { addr = raw_local_address },
					remote = NGTcp2.Address () { addr = raw_remote_address },
				};

				unowned uint8[] data = rx_buf[:n];

				var res = connection.read_packet (path, null, data, make_timestamp ());
				if (res == NGTcp2.ErrorCode.DRAINING)
					perform_teardown ();
			} catch (GLib.Error e) {
				return Source.REMOVE;
			} finally {
				process_pending_writes ();
			}

			return Source.CONTINUE;
		}

		private void process_pending_writes () {
			if (connection == null || write_idle != null)
				return;

			var source = new IdleSource ();
			source.set_callback (() => {
				write_idle = null;
				do_process_pending_writes ();
				return Source.REMOVE;
			});
			source.attach (main_context);
			write_idle = source;
		}

		private void do_process_pending_writes () {
			var ts = make_timestamp ();

			var pi = NGTcp2.PacketInfo ();
			Gee.Iterator<Stream> stream_iter = streams.values.iterator ();
			while (true) {
				ssize_t n = -1;

				if (state == CLOSE_SCHEDULED) {
					var error = NGTcp2.ConnectionError.application (0);
					n = connection.write_connection_close (null, &pi, tx_buf, error, ts);
					state = CLOSE_WRITTEN;
				} else {
					Bytes? datagram = tx_datagrams.peek ();
					if (datagram != null) {
						int accepted = -1;
						n = connection.write_datagram (null, null, tx_buf, &accepted, NGTcp2.WriteDatagramFlags.MORE, 0,
							datagram.get_data (), ts);
						if (accepted > 0)
							tx_datagrams.poll ();
					} else {
						Stream? stream = null;
						unowned uint8[]? data = null;
						NGTcp2.WriteStreamFlags stream_flags = MORE;

						while (stream == null && stream_iter.next ()) {
							Stream s = stream_iter.get ();
							uint64 len = s.tx_buf.len;
							uint64 limit = 0;

							if (len != 0 && (limit = connection.get_max_stream_data_left (s.id)) != 0) {
								stream = s;
								data = s.tx_buf.data[:(int) uint64.min (len, limit)];
								break;
							}
						}

						ssize_t datalen = 0;
						n = connection.write_stream (null, &pi, tx_buf, &datalen, stream_flags,
							(stream != null) ? stream.id : -1, data, ts);
						if (datalen > 0)
							stream.tx_buf.remove_range (0, (uint) datalen);
					}
				}

				if (n == 0)
					break;
				if (n == NGTcp2.ErrorCode.WRITE_MORE)
					continue;
				if (n == NGTcp2.ErrorCode.CLOSING) {
					perform_teardown ();
					break;
				}
				if (n < 0)
					break;

				try {
					Udp.send (tx_buf[:n], socket.datagram_based, io_cancellable);
				} catch (GLib.Error e) {
					continue;
				}
			}

			if (expiry_timer != null) {
				expiry_timer.destroy ();
				expiry_timer = null;
			}

			if (close_request.future.ready)
				return;

			NGTcp2.Timestamp expiry = connection.get_expiry ();
			if (expiry == uint64.MAX)
				return;

			NGTcp2.Timestamp now = make_timestamp ();

			uint delta_msec;
			if (expiry > now) {
				uint64 delta_nsec = expiry - now;
				delta_msec = (uint) (delta_nsec / 1000000ULL);
			} else {
				delta_msec = 1;
			}

			var source = new TimeoutSource (delta_msec);
			source.set_callback (on_expiry);
			source.attach (main_context);
			expiry_timer = source;
		}

		private bool on_expiry () {
			int res = connection.handle_expiry (make_timestamp ());
			if (res != 0) {
				perform_teardown ();
				return Source.REMOVE;
			}

			process_pending_writes ();

			return Source.REMOVE;
		}

		private static int on_get_new_connection_id (NGTcp2.Connection conn, out NGTcp2.ConnectionID cid, uint8[] token,
				size_t cidlen, void * user_data) {
			cid = make_connection_id (cidlen);

			OpenSSL.Rng.generate (token[:NGTcp2.STATELESS_RESET_TOKENLEN]);

			return 0;
		}

		private int on_extend_max_local_streams_bidi (uint64 max_streams) {
			if (control_stream == null) {
				control_stream = open_bidi_stream ();

				var source = new IdleSource ();
				source.set_callback (() => {
					on_control_stream_opened ();
					return Source.REMOVE;
				});
				source.attach (main_context);
			}

			return 0;
		}

		private int on_stream_close (uint32 flags, int64 stream_id, uint64 app_error_code) {
			if (!establish_request.future.ready) {
				establish_request.reject (new Error.TRANSPORT ("Connection closed early with QUIC app error code %" +
					uint64.FORMAT_MODIFIER + "u", app_error_code));
			}

			perform_teardown ();

			return 0;
		}

		private int on_recv_stream_data (uint32 flags, int64 stream_id, uint64 offset, uint8[] data) {
			Stream? stream = streams[stream_id];
			if (stream != null)
				stream.on_recv (data);

			return 0;
		}

		private int on_recv_datagram (uint32 flags, uint8[] data) {
			try {
				_tunnel_netstack.handle_incoming_datagram (new Bytes (data));
			} catch (Error e) {
			}

			return 0;
		}

		private static void on_rand (uint8[] dest, NGTcp2.RNGContext rand_ctx) {
			OpenSSL.Rng.generate (dest);
		}

		private static uint8[] address_to_native (SocketAddress address) {
			var size = address.get_native_size ();
			var buf = new uint8[size];
			try {
				address.to_native (buf, size);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			return buf;
		}

		private static NGTcp2.ConnectionID make_connection_id (size_t len) {
			var cid = NGTcp2.ConnectionID () {
				datalen = len,
			};

			NGTcp2.ConnectionID * mutable_cid = &cid;
			OpenSSL.Rng.generate (mutable_cid->data[:len]);

			return cid;
		}

		private static NGTcp2.Timestamp make_timestamp () {
			return get_monotonic_time () * NGTcp2.MICROSECONDS;
		}

		private static X509 make_certificate (Key keypair) {
			var cert = new X509 ();
			cert.get_serial_number ().set_uint64 (1);
			cert.get_not_before ().adjust (0);
			cert.get_not_after ().adjust (5260000);

			unowned X509.Name name = cert.get_subject_name ();
			cert.set_issuer_name (name);
			cert.set_pubkey (keypair);

			var mc = new MessageDigestContext ();
			mc.digest_sign_init (null, null, null, keypair);
			cert.sign_ctx (mc);

			return cert;
		}

		private Stream open_bidi_stream () {
			int64 id;
			connection.open_bidi_stream (out id, null);

			var stream = new Stream (this, id);
			streams[id] = stream;

			return stream;
		}

		private class Stream {
			public int64 id;

			private weak QuicTunnelConnection parent;

			public ByteArray rx_buf = new ByteArray.sized (256);
			public ByteArray tx_buf = new ByteArray.sized (128);

			public Stream (QuicTunnelConnection parent, int64 id) {
				this.parent = parent;
				this.id = id;
			}

			public void send (uint8[] data) {
				tx_buf.append (data);
				parent.process_pending_writes ();
			}

			public void on_recv (uint8[] data) {
				rx_buf.append (data);

				size_t consumed;
				parent.on_stream_data_available (this, rx_buf.data, out consumed);

				if (consumed != 0)
					rx_buf.remove_range (0, (uint) consumed);
			}
		}
	}

	public sealed class TunnelKey {
		public Key handle;

		public TunnelKey (owned Key handle) {
			this.handle = (owned) handle;
		}
	}

	public class AppService : TrustedService {
		public static async AppService open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var service = new AppService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private AppService (IOStream stream) {
			Object (stream: stream);
		}

		public async Gee.List<ApplicationInfo> enumerate_applications (Cancellable? cancellable = null) throws Error, IOError {
			Bytes input = new XpcObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("includeDefaultApps")
					.add_bool_value (true)
					.set_member_name ("includeRemovableApps")
					.add_bool_value (true)
					.set_member_name ("includeInternalApps")
					.add_bool_value (true)
					.set_member_name ("includeHiddenApps")
					.add_bool_value (true)
					.set_member_name ("includeAppClips")
					.add_bool_value (true)
				.end_dictionary ()
				.build ();
			var response = yield invoke ("com.apple.coredevice.feature.listapps", input, cancellable);

			var applications = new Gee.ArrayList<ApplicationInfo> ();
			uint n = response.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);

				string bundle_identifier = response
					.read_member ("bundleIdentifier")
					.get_string_value ();
				response.end_member ();

				string? bundle_version = null;
				if (response.has_member ("bundleVersion")) {
					bundle_version = response
						.read_member ("bundleVersion")
						.get_string_value ();
					response.end_member ();
				}

				string name = response
					.read_member ("name")
					.get_string_value ();
				response.end_member ();

				string? version = null;
				if (response.has_member ("version")) {
					version = response
						.read_member ("version")
						.get_string_value ();
					response.end_member ();
				}

				string path = response
					.read_member ("path")
					.get_string_value ();
				response.end_member ();

				bool is_first_party = response
					.read_member ("isFirstParty")
					.get_bool_value ();
				response.end_member ();

				bool is_developer_app = response
					.read_member ("isDeveloperApp")
					.get_bool_value ();
				response.end_member ();

				bool is_removable = response
					.read_member ("isRemovable")
					.get_bool_value ();
				response.end_member ();

				bool is_internal = response
					.read_member ("isInternal")
					.get_bool_value ();
				response.end_member ();

				bool is_hidden = response
					.read_member ("isHidden")
					.get_bool_value ();
				response.end_member ();

				bool is_app_clip = response
					.read_member ("isAppClip")
					.get_bool_value ();
				response.end_member ();

				applications.add (new ApplicationInfo () {
					bundle_identifier = bundle_identifier,
					bundle_version = bundle_version,
					name = name,
					version = version,
					path = path,
					is_first_party = is_first_party,
					is_developer_app = is_developer_app,
					is_removable = is_removable,
					is_internal = is_internal,
					is_hidden = is_hidden,
					is_app_clip = is_app_clip,
				});

				response.end_element ();
			}

			return applications;
		}

		public async Gee.List<ProcessInfo> enumerate_processes (Cancellable? cancellable = null) throws Error, IOError {
			var response = yield invoke ("com.apple.coredevice.feature.listprocesses", null, cancellable);

			var processes = new Gee.ArrayList<ProcessInfo> ();
			uint n = response
				.read_member ("processTokens")
				.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);

				int64 pid = response
					.read_member ("processIdentifier")
					.get_int64_value ();
				response.end_member ();

				string url = response
					.read_member ("executableURL")
					.read_member ("relative")
					.get_string_value ();
				response
					.end_member ()
					.end_member ();

				if (!url.has_prefix ("file://"))
					throw new Error.PROTOCOL ("Unsupported URL: %s", url);

				string path = url[7:];

				processes.add (new ProcessInfo () {
					pid = (uint) pid,
					path = path,
				});

				response.end_element ();
			}

			return processes;
		}

		public class ApplicationInfo {
			public string bundle_identifier;
			public string? bundle_version;
			public string name;
			public string? version;
			public string path;
			public bool is_first_party;
			public bool is_developer_app;
			public bool is_removable;
			public bool is_internal;
			public bool is_hidden;
			public bool is_app_clip;
		}

		public class ProcessInfo {
			public uint pid;
			public string path;
		}
	}

	public abstract class TrustedService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private XpcConnection connection;

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			connection = new XpcConnection (stream);
			connection.activate ();

			return true;
		}

		public void close () {
			connection.cancel ();
		}

		protected async VariantReader invoke (string feature_identifier, Bytes? input = null, Cancellable? cancellable)
				throws Error, IOError {
			var request = new XpcBodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("CoreDevice.featureIdentifier")
					.add_string_value (feature_identifier)
					.set_member_name ("CoreDevice.action")
					.begin_dictionary ()
					.end_dictionary ()
					.set_member_name ("CoreDevice.input");

			if (input != null)
				request.add_raw_value (input);
			else
				request.add_null_value ();

			add_standard_request_values (request);
			request.end_dictionary ();

			XpcMessage raw_response = yield connection.request (request.build (), cancellable);

			var response = new VariantReader (raw_response.body);
			response.read_member ("CoreDevice.output");
			return response;
		}

		public static void add_standard_request_values (ObjectBuilder builder) {
			builder
				.set_member_name ("CoreDevice.invocationIdentifier")
				.add_string_value (Uuid.string_random ().up ())
				.set_member_name ("CoreDevice.CoreDeviceDDIProtocolVersion")
				.add_int64_value (0)
				.set_member_name ("CoreDevice.coreDeviceVersion")
				.begin_dictionary ()
					.set_member_name ("originalComponentsCount")
					.add_int64_value (2)
					.set_member_name ("components")
					.begin_array ()
						.add_uint64_value (348)
						.add_uint64_value (1)
						.add_uint64_value (0)
						.add_uint64_value (0)
						.add_uint64_value (0)
					.end_array ()
					.set_member_name ("stringValue")
					.add_string_value ("348.1")
				.end_dictionary ()
				.set_member_name ("CoreDevice.deviceIdentifier")
				.add_string_value (make_host_identifier ());
		}
	}

	public sealed class XpcConnection : Object {
		public signal void close (Error? error);
		public signal void message (XpcMessage msg);

		public IOStream stream {
			get;
			construct;
		}

		public State state {
			get;
			private set;
			default = INACTIVE;
		}

		private Error? pending_error;

		private Promise<bool> ready = new Promise<bool> ();
		private XpcMessage? root_helo;
		private XpcMessage? reply_helo;
		private Gee.Map<uint64?, PendingResponse> pending_responses =
			new Gee.HashMap<uint64?, PendingResponse> (Numeric.uint64_hash, Numeric.uint64_equal);

		private NGHttp2.Session session;
		private Stream root_stream;
		private Stream reply_stream;
		private uint next_message_id = 1;

		private bool is_processing_messages;

		private ByteArray? send_queue;
		private Source? send_source;

		private Cancellable io_cancellable = new Cancellable ();

		public enum State {
			INACTIVE,
			ACTIVE,
			CLOSED,
		}

		public XpcConnection (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			NGHttp2.SessionCallbacks callbacks;
			NGHttp2.SessionCallbacks.make (out callbacks);

			callbacks.set_send_callback ((session, data, flags, user_data) => {
				XpcConnection * self = user_data;
				return self->on_send (data, flags);
			});
			callbacks.set_on_frame_send_callback ((session, frame, user_data) => {
				XpcConnection * self = user_data;
				return self->on_frame_send (frame);
			});
			callbacks.set_on_frame_not_send_callback ((session, frame, lib_error_code, user_data) => {
				XpcConnection * self = user_data;
				return self->on_frame_not_send (frame, lib_error_code);
			});
			callbacks.set_on_data_chunk_recv_callback ((session, flags, stream_id, data, user_data) => {
				XpcConnection * self = user_data;
				return self->on_data_chunk_recv (flags, stream_id, data);
			});
			callbacks.set_on_frame_recv_callback ((session, frame, user_data) => {
				XpcConnection * self = user_data;
				return self->on_frame_recv (frame);
			});
			callbacks.set_on_stream_close_callback ((session, stream_id, error_code, user_data) => {
				XpcConnection * self = user_data;
				return self->on_stream_close (stream_id, error_code);
			});

			NGHttp2.Option option;
			NGHttp2.Option.make (out option);
			option.set_no_auto_window_update (true);
			option.set_peer_max_concurrent_streams (100);
			option.set_no_http_messaging (true);
			// option.set_no_http_semantics (true);
			option.set_no_closed_streams (true);

			NGHttp2.Session.make_client (out session, callbacks, this, option);
		}

		public void activate () {
			do_activate.begin ();
		}

		private async void do_activate () {
			try {
				is_processing_messages = true;
				process_incoming_messages.begin ();

				session.submit_settings (NGHttp2.Flag.NONE, {
					{ MAX_CONCURRENT_STREAMS, 100 },
					{ INITIAL_WINDOW_SIZE, 1048576 },
				});

				session.set_local_window_size (NGHttp2.Flag.NONE, 0, 1048576);

				root_stream = make_stream ();

				Bytes header_request = new XpcMessageBuilder (HEADER)
					.add_body (new XpcBodyBuilder ()
						.begin_dictionary ()
						.end_dictionary ()
						.build ()
					)
					.build ();
				yield root_stream.submit_data (header_request, io_cancellable);

				Bytes ping_request = new XpcMessageBuilder (PING)
					.build ();
				yield root_stream.submit_data (ping_request, io_cancellable);

				reply_stream = make_stream ();

				Bytes open_reply_channel_request = new XpcMessageBuilder (HEADER)
					.add_flags (HEADER_OPENS_REPLY_CHANNEL)
					.build ();
				yield reply_stream.submit_data (open_reply_channel_request, io_cancellable);
			} catch (GLib.Error e) {
				if (e is Error && pending_error == null)
					pending_error = (Error) e;
				cancel ();
			}
		}

		public void cancel () {
			io_cancellable.cancel ();
		}

		public async PeerInfo wait_until_ready (Cancellable? cancellable = null) throws Error, IOError {
			yield ready.future.wait_async (cancellable);

			return new PeerInfo () {
				metadata = root_helo.body,
			};
		}

		public async XpcMessage request (Bytes body, Cancellable? cancellable = null) throws Error, IOError {
			uint64 request_id = make_message_id ();

			Bytes raw_request = new XpcMessageBuilder (MSG)
				.add_flags (WANTS_REPLY)
				.add_id (request_id)
				.add_body (body)
				.build ();

			bool waiting = false;

			var pending = new PendingResponse (() => {
				if (waiting)
					request.callback ();
				return Source.REMOVE;
			});
			pending_responses[request_id] = pending;

			try {
				yield root_stream.submit_data (raw_request, cancellable);
			} catch (Error e) {
				if (pending_responses.unset (request_id))
					pending.complete_with_error (e);
			}

			if (!pending.completed) {
				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (() => {
					if (pending_responses.unset (request_id))
						pending.complete_with_error (new IOError.CANCELLED ("Operation was cancelled"));
					return false;
				});
				cancel_source.attach (MainContext.get_thread_default ());

				waiting = true;
				yield;
				waiting = false;

				cancel_source.destroy ();
			}

			cancellable.set_error_if_cancelled ();

			if (pending.error != null)
				throw_api_error (pending.error);

			return pending.result;
		}

		private class PendingResponse {
			private SourceFunc? handler;

			public bool completed {
				get {
					return result != null || error != null;
				}
			}

			public XpcMessage? result {
				get;
				private set;
			}

			public GLib.Error? error {
				get;
				private set;
			}

			public PendingResponse (owned SourceFunc handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_result (XpcMessage result) {
				if (completed)
					return;
				this.result = result;
				handler ();
				handler = null;
			}

			public void complete_with_error (GLib.Error error) {
				if (completed)
					return;
				this.error = error;
				handler ();
				handler = null;
			}
		}

		public async void post (Bytes body, Cancellable? cancellable = null) throws Error, IOError {
			Bytes raw_request = new XpcMessageBuilder (MSG)
				.add_id (make_message_id ())
				.add_body (body)
				.build ();

			yield root_stream.submit_data (raw_request, cancellable);
		}

		private void on_header (XpcMessage msg, Stream sender) {
			if (sender == root_stream) {
				if (root_helo == null)
					root_helo = msg;
			} else if (sender == reply_stream) {
				if (reply_helo == null)
					reply_helo = msg;
			}

			if (!ready.future.ready && root_helo != null && reply_helo != null)
				ready.resolve (true);
		}

		private void on_reply (XpcMessage msg, Stream sender) {
			if (sender != reply_stream)
				return;

			PendingResponse response;
			if (!pending_responses.unset (msg.id, out response))
				return;

			if (msg.body != null)
				response.complete_with_result (msg);
			else
				response.complete_with_error (new Error.NOT_SUPPORTED ("Request not supported"));
		}

		private void maybe_send_pending () {
			while (session.want_write ()) {
				bool would_block = send_source != null && send_queue == null;
				if (would_block)
					break;

				session.send ();
			}
		}

		private async void process_incoming_messages () {
			InputStream input = stream.get_input_stream ();

			var buffer = new uint8[4096];

			while (is_processing_messages) {
				try {
					ssize_t n = yield input.read_async (buffer, Priority.DEFAULT, io_cancellable);
					if (n == 0) {
						is_processing_messages = false;
						continue;
					}

					ssize_t result = session.mem_recv (buffer[:n]);
					if (result < 0)
						throw new Error.PROTOCOL ("%s", NGHttp2.strerror (result));

					session.consume_connection (n);
				} catch (GLib.Error e) {
					if (e is Error && pending_error == null)
						pending_error = (Error) e;
					is_processing_messages = false;
				}
			}

			Error error = (pending_error != null)
				? pending_error
				: new Error.TRANSPORT ("Connection closed");

			foreach (var r in pending_responses.values.to_array ())
				r.complete_with_error (error);
			pending_responses.clear ();

			if (!ready.future.ready)
				ready.reject (error);

			state = CLOSED;

			close (pending_error);
			pending_error = null;
		}

		private ssize_t on_send (uint8[] data, int flags) {
			if (send_source == null) {
				send_queue = new ByteArray.sized (1024);

				var source = new IdleSource ();
				source.set_callback (() => {
					do_send.begin ();
					return Source.REMOVE;
				});
				source.attach (MainContext.get_thread_default ());
				send_source = source;
			}

			if (send_queue == null)
				return NGHttp2.ErrorCode.WOULDBLOCK;

			send_queue.append (data);
			return data.length;
		}

		private async void do_send () {
			uint8[] buffer = send_queue.steal ();
			send_queue = null;

			try {
				size_t bytes_written;
				yield stream.get_output_stream ().write_all_async (buffer, Priority.DEFAULT, io_cancellable,
					out bytes_written);
			} catch (GLib.Error e) {
			}

			send_source = null;

			maybe_send_pending ();
		}

		private int on_frame_send (NGHttp2.Frame frame) {
			if (frame.hd.type == DATA)
				find_stream_by_id (frame.hd.stream_id).on_data_frame_send ();
			return 0;
		}

		private int on_frame_not_send (NGHttp2.Frame frame, NGHttp2.ErrorCode lib_error_code) {
			if (frame.hd.type == DATA)
				find_stream_by_id (frame.hd.stream_id).on_data_frame_not_send (lib_error_code);
			return 0;
		}

		private int on_data_chunk_recv (uint8 flags, int32 stream_id, uint8[] data) {
			return find_stream_by_id (stream_id).on_data_frame_recv_chunk (data);
		}

		private int on_frame_recv (NGHttp2.Frame frame) {
			if (frame.hd.type == DATA)
				return find_stream_by_id (frame.hd.stream_id).on_data_frame_recv_end (frame);
			return 0;
		}

		private int on_stream_close (int32 stream_id, uint32 error_code) {
			io_cancellable.cancel ();
			return 0;
		}

		private Stream make_stream () {
			int stream_id = session.submit_headers (NGHttp2.Flag.NONE, -1, null, {}, null);
			maybe_send_pending ();

			return new Stream (this, stream_id);
		}

		private Stream? find_stream_by_id (int32 id) {
			if (root_stream.id == id)
				return root_stream;
			if (reply_stream.id == id)
				return reply_stream;
			return null;
		}

		private uint make_message_id () {
			uint id = next_message_id;
			next_message_id += 2;
			return id;
		}

		private class Stream {
			public int32 id;

			private weak XpcConnection parent;

			private Gee.Deque<SubmitOperation> submissions = new Gee.ArrayQueue<SubmitOperation> ();
			private SubmitOperation? current_submission = null;
			private ByteArray incoming_message = new ByteArray ();

			public Stream (XpcConnection parent, int32 id) {
				this.parent = parent;
				this.id = id;
			}

			public async void submit_data (Bytes bytes, Cancellable? cancellable) throws Error, IOError {
				bool waiting = false;

				var op = new SubmitOperation (bytes, () => {
					if (waiting)
						submit_data.callback ();
					return Source.REMOVE;
				});

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (() => {
					op.state = CANCELLED;
					op.callback ();
					return Source.REMOVE;
				});
				cancel_source.attach (MainContext.get_thread_default ());

				submissions.offer_tail (op);
				maybe_submit_data ();

				if (op.state < SubmitOperation.State.SUBMITTED) {
					waiting = true;
					yield;
					waiting = false;
				}

				cancel_source.destroy ();

				if (op.state == CANCELLED && current_submission != op)
					submissions.remove (op);
```