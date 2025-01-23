Response:
### 功能归纳

`xpc.vala` 文件是 Frida 工具中用于处理与 iOS 设备通信的核心模块之一，主要功能是通过 XPC（XNU 进程间通信）协议与 iOS 设备进行通信。以下是该文件的主要功能归纳：

1. **设备发现与服务管理**：
   - `DiscoveryService` 类负责与 iOS 设备建立连接，并处理设备的发现和服务查询。
   - 通过 `query_udid()` 方法可以查询设备的唯一标识符（UDID）。
   - 通过 `get_service()` 方法可以获取设备上特定服务的端口信息。

2. **设备配对与加密通信**：
   - `PairingService` 类负责与 iOS 设备进行配对，并建立加密通信通道。
   - 使用 `ChaCha20Poly1305` 加密算法对通信数据进行加密和解密。
   - 通过 `SRPClientSession` 类实现安全远程密码（SRP）协议，用于设备配对的密钥交换和验证。

3. **隧道连接**：
   - `open_tunnel()` 方法用于在设备和主机之间建立隧道连接，支持 TCP 和 QUIC 协议。
   - 隧道连接可以用于在设备和主机之间传输数据，支持加密通信。

4. **消息处理与序列化**：
   - 通过 `VariantReader` 和 `VariantWriter` 类处理 XPC 消息的序列化和反序列化。
   - 使用 `XpcBodyBuilder` 类构建 XPC 消息体。

5. **错误处理与重试机制**：
   - 在配对过程中，如果设备返回错误或配对失败，会触发相应的错误处理机制。
   - 支持重试机制，例如在配对失败后可以重新尝试配对。

### 涉及到的二进制底层与 Linux 内核

- **XPC 协议**：XPC 是 macOS 和 iOS 中的一种进程间通信机制，基于 Mach 内核的消息传递机制。虽然 XPC 主要用于 macOS 和 iOS，但其底层实现与 Linux 内核中的 IPC（进程间通信）机制有相似之处。
- **加密算法**：`ChaCha20Poly1305` 是一种对称加密算法，常用于加密通信。该算法的实现依赖于底层的加密库（如 OpenSSL）。
- **SRP 协议**：SRP（Secure Remote Password）协议是一种用于安全密码验证的协议，常用于设备配对和密钥交换。SRP 协议的实现涉及到大量的数学运算，如大数运算和哈希计算。

### 使用 LLDB 调试的示例

假设我们想要调试 `DiscoveryService` 类的 `query_udid()` 方法，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令示例

```bash
# 启动 LLDB 并附加到 Frida 进程
lldb frida

# 设置断点
b frida::Fruity::DiscoveryService::query_udid

# 运行程序
run

# 当断点触发时，查看变量
p handshake_body
p connection
```

#### LLDB Python 脚本示例

```python
import lldb

def query_udid_breakpoint(frame, bp_loc, dict):
    # 获取 handshake_body 变量
    handshake_body = frame.FindVariable("handshake_body")
    print("handshake_body: ", handshake_body.GetValue())

    # 获取 connection 变量
    connection = frame.FindVariable("connection")
    print("connection: ", connection.GetValue())

    # 继续执行
    return False

# 创建调试器实例
debugger = lldb.SBDebugger.Create()
debugger.SetAsync(True)

# 附加到 Frida 进程
target = debugger.CreateTarget("frida")
process = target.AttachToProcessWithName("frida", False)

# 设置断点
breakpoint = target.BreakpointCreateByName("frida::Fruity::DiscoveryService::query_udid")
breakpoint.SetScriptCallbackFunction("query_udid_breakpoint")

# 运行程序
process.Continue()
```

### 假设输入与输出

假设我们调用 `query_udid()` 方法，输入为设备的 XPC 连接，输出为设备的 UDID。

- **输入**：设备的 XPC 连接（`connection`）和握手消息体（`handshake_body`）。
- **输出**：设备的 UDID（字符串）。

### 常见使用错误

1. **设备未连接**：如果设备未连接或 XPC 连接未建立，调用 `query_udid()` 方法会抛出 `Error.TRANSPORT` 错误。
   - **示例**：`Error.TRANSPORT: XpcConnection closed while waiting for Handshake message`

2. **服务未找到**：如果查询的服务标识符不存在，`get_service()` 方法会抛出 `Error.NOT_SUPPORTED` 错误。
   - **示例**：`Error.NOT_SUPPORTED: Service 'com.example.service' not found`

3. **配对失败**：如果设备配对失败，`PairingService` 会抛出 `Error.PROTOCOL` 错误。
   - **示例**：`Error.PROTOCOL: Invalid proof`

### 用户操作步骤

1. **启动 Frida**：用户启动 Frida 工具，并尝试连接到 iOS 设备。
2. **设备发现**：Frida 通过 `DiscoveryService` 类发现设备，并建立 XPC 连接。
3. **查询 UDID**：用户调用 `query_udid()` 方法，Frida 从握手消息体中提取设备的 UDID。
4. **配对设备**：如果设备未配对，Frida 通过 `PairingService` 类与设备进行配对，并建立加密通信通道。
5. **建立隧道**：用户调用 `open_tunnel()` 方法，Frida 在设备和主机之间建立隧道连接，用于数据传输。

通过这些步骤，用户可以逐步调试和排查 Frida 与 iOS 设备通信中的问题。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/xpc.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	using OpenSSL;
	using OpenSSL.Envelope;

	public class DiscoveryService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private XpcConnection connection;

		private Promise<Variant> handshake_promise = new Promise<Variant> ();
		private Variant handshake_body;

		private Cancellable io_cancellable = new Cancellable ();

		public static async DiscoveryService open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var service = new DiscoveryService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private DiscoveryService (IOStream stream) {
			Object (stream: stream);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			connection = new XpcConnection (stream);
			connection.close.connect (on_close);
			connection.message.connect (on_message);
			connection.activate ();

			handshake_body = yield handshake_promise.future.wait_async (cancellable);

			return true;
		}

		public void close () {
			io_cancellable.cancel ();
			connection.cancel ();
		}

		public string query_udid () throws Error {
			var reader = new VariantReader (handshake_body);
			reader
				.read_member ("Properties")
				.read_member ("UniqueDeviceID");
			return reader.get_string_value ();
		}

		public ServiceInfo get_service (string identifier) throws Error {
			var reader = new VariantReader (handshake_body);
			reader.read_member ("Services");
			try {
				reader.read_member (identifier);
			} catch (Error e) {
				throw new Error.NOT_SUPPORTED ("Service '%s' not found", identifier);
			}

			var port = (uint16) uint.parse (reader.read_member ("Port").get_string_value ());

			return new ServiceInfo () {
				port = port,
			};
		}

		private void on_close (Error? error) {
			if (!handshake_promise.future.ready) {
				handshake_promise.reject (
					(error != null)
						? error
						: new Error.TRANSPORT ("XpcConnection closed while waiting for Handshake message"));
			}
		}

		private void on_message (XpcMessage msg) {
			if (msg.body == null)
				return;

			var reader = new VariantReader (msg.body);
			try {
				reader.read_member ("MessageType");
				unowned string message_type = reader.get_string_value ();

				if (message_type == "Handshake") {
					handshake_promise.resolve (msg.body);

					connection.post.begin (
						new XpcBodyBuilder ()
							.begin_dictionary ()
								.set_member_name ("MessageType")
								.add_string_value ("Handshake")
								.set_member_name ("MessagingProtocolVersion")
								.add_uint64_value (5)
								.set_member_name ("Services")
								.begin_dictionary ()
								.end_dictionary ()
								.set_member_name ("Properties")
								.begin_dictionary ()
									.set_member_name ("RemoteXPCVersionFlags")
									.add_uint64_value (0x100000000000006)
								.end_dictionary ()
								.set_member_name ("UUID")
								.add_uuid_value (make_random_v4_uuid ())
							.end_dictionary ()
							.build (),
						io_cancellable);
				}
			} catch (Error e) {
			}
		}
	}

	public class ServiceInfo {
		public uint16 port;
	}

	public class PairingService : Object, AsyncInitable {
		public const string DNS_SD_NAME = "_remotepairing._tcp.local";

		public PairingTransport transport {
			get;
			construct;
		}

		public PairingStore store {
			get;
			construct;
		}

		public DeviceOptions device_options {
			get;
			private set;
		}

		public DeviceInfo? device_info {
			get;
			private set;
		}

		private Gee.Map<uint64?, Promise<ObjectReader>> requests =
			new Gee.HashMap<uint64?, Promise<ObjectReader>> (Numeric.uint64_hash, Numeric.uint64_equal);
		private uint64 next_control_sequence_number = 0;
		private uint64 next_encrypted_sequence_number = 0;

		private ChaCha20Poly1305? client_cipher;
		private ChaCha20Poly1305? server_cipher;

		public static async PairingService open (PairingTransport transport, PairingStore store, Cancellable? cancellable = null)
				throws Error, IOError {
			var service = new PairingService (transport, store);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private PairingService (PairingTransport transport, PairingStore store) {
			Object (transport: transport, store: store);
		}

		construct {
			transport.close.connect (on_close);
			transport.message.connect (on_message);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			yield transport.open (cancellable);

			yield attempt_pair_verify (cancellable);

			Bytes? shared_key = yield verify_manual_pairing (cancellable);
			if (shared_key == null) {
				if (!device_options.allows_pair_setup)
					throw new Error.NOT_SUPPORTED ("Device not paired and pairing not allowed on current transport");
				shared_key = yield setup_manual_pairing (cancellable);
			}

			client_cipher = new ChaCha20Poly1305 (derive_chacha_key (shared_key, "ClientEncrypt-main"));
			server_cipher = new ChaCha20Poly1305 (derive_chacha_key (shared_key, "ServerEncrypt-main"));

			return true;
		}

		public void close () {
			transport.cancel ();
		}

		public async TunnelConnection open_tunnel (InetAddress device_address, NetworkStack netstack,
				Cancellable? cancellable = null) throws Error, IOError {
			string? protocol = Environment.get_variable ("FRIDA_FRUITY_TUNNEL_PROTOCOL");
			if (protocol == null)
				protocol = "tcp";

			Key local_keypair;
			uint8[] key;
			if (protocol == "quic") {
				local_keypair = make_keypair (RSA);
				key = key_to_der (local_keypair);
			} else {
				local_keypair = make_keypair (ED25519);
				key = get_raw_private_key (local_keypair).get_data ();
			}

			string request = Json.to_string (
				new Json.Builder ()
				.begin_object ()
					.set_member_name ("request")
					.begin_object ()
						.set_member_name ("_0")
						.begin_object ()
							.set_member_name ("createListener")
							.begin_object ()
								.set_member_name ("transportProtocolType")
								.add_string_value (protocol)
								.set_member_name ("key")
								.add_string_value (Base64.encode (key))
							.end_object ()
						.end_object ()
					.end_object ()
				.end_object ()
				.get_root (), false);

			string response = yield request_encrypted (request, cancellable);

			Json.Reader reader;
			try {
				reader = new Json.Reader (Json.from_string (response));
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Invalid response JSON");
			}

			reader.read_member ("response");
			reader.read_member ("_1");
			reader.read_member ("createListener");

			if (!reader.read_member ("devicePublicKey"))
				throw new Error.NOT_SUPPORTED ("Unsupported tunnel service");
			string? device_pubkey = reader.get_string_value ();
			reader.end_member ();

			reader.read_member ("port");
			uint16 port = (uint16) reader.get_int_value ();
			reader.end_member ();

			GLib.Error? error = reader.get_error ();
			if (error != null)
				throw new Error.PROTOCOL ("Invalid response: %s", error.message);

			Key remote_pubkey = key_from_der (Base64.decode (device_pubkey));

			var tunnel_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: device_address,
				port: port,
				scope_id: netstack.scope_id
			);

			if (protocol == "quic") {
				return yield QuicTunnelConnection.open (
					tunnel_endpoint,
					netstack,
					new TunnelKey ((owned) local_keypair),
					new TunnelKey ((owned) remote_pubkey),
					cancellable);
			} else {
				return yield TcpTunnelConnection.open (
					tunnel_endpoint,
					netstack,
					new TunnelKey ((owned) local_keypair),
					new TunnelKey ((owned) remote_pubkey),
					cancellable);
			}
		}

		private async void attempt_pair_verify (Cancellable? cancellable) throws Error, IOError {
			Bytes payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("request")
					.begin_dictionary ()
						.set_member_name ("_0")
						.begin_dictionary ()
							.set_member_name ("handshake")
							.begin_dictionary ()
								.set_member_name ("_0")
								.begin_dictionary ()
									.set_member_name ("wireProtocolVersion")
									.add_int64_value (19)
									.set_member_name ("hostOptions")
									.begin_dictionary ()
										.set_member_name ("attemptPairVerify")
										.add_bool_value (true)
									.end_dictionary ()
								.end_dictionary ()
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();

			ObjectReader response = yield request_plain (payload, cancellable);

			response
				.read_member ("response")
				.read_member ("_1")
				.read_member ("handshake")
				.read_member ("_0");

			response.read_member ("deviceOptions");

			bool allows_pair_setup = response.read_member ("allowsPairSetup").get_bool_value ();
			response.end_member ();

			bool allows_pinless_pairing = response.read_member ("allowsPinlessPairing").get_bool_value ();
			response.end_member ();

			bool allows_promptless_automation_pairing_upgrade =
				response.read_member ("allowsPromptlessAutomationPairingUpgrade").get_bool_value ();
			response.end_member ();

			bool allows_sharing_sensitive_info = response.read_member ("allowsSharingSensitiveInfo").get_bool_value ();
			response.end_member ();

			bool allows_incoming_tunnel_connections =
				response.read_member ("allowsIncomingTunnelConnections").get_bool_value ();
			response.end_member ();

			device_options = new DeviceOptions () {
				allows_pair_setup = allows_pair_setup,
				allows_pinless_pairing = allows_pinless_pairing,
				allows_promptless_automation_pairing_upgrade = allows_promptless_automation_pairing_upgrade,
				allows_sharing_sensitive_info = allows_sharing_sensitive_info,
				allows_incoming_tunnel_connections = allows_incoming_tunnel_connections,
			};

			if (response.has_member ("peerDeviceInfo")) {
				response.read_member ("peerDeviceInfo");

				string name = response.read_member ("name").get_string_value ();
				response.end_member ();

				string model = response.read_member ("model").get_string_value ();
				response.end_member ();

				string udid = response.read_member ("udid").get_string_value ();
				response.end_member ();

				uint64 ecid = response.read_member ("ecid").get_uint64_value ();
				response.end_member ();

				Plist kvs;
				try {
					kvs = new Plist.from_binary (response.read_member ("deviceKVSData").get_data_value ().get_data ());
					response.end_member ();
				} catch (PlistError e) {
					throw new Error.PROTOCOL ("%s", e.message);
				}

				device_info = new DeviceInfo () {
					name = name,
					model = model,
					udid = udid,
					ecid = ecid,
					kvs = kvs,
				};
			}
		}

		private async Bytes? verify_manual_pairing (Cancellable? cancellable) throws Error, IOError {
			Key host_keypair = make_keypair (X25519);
			uint8[] raw_host_pubkey = get_raw_public_key (host_keypair).get_data ();

			Bytes start_params = new PairingParamsBuilder ()
				.add_state (1)
				.add_public_key (host_keypair)
				.build ();

			Bytes start_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("verifyManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (true)
					.set_member_name ("data")
					.add_data_value (start_params)
				.end_dictionary ()
				.build ();

			var start_response = yield request_pairing_data (start_payload, cancellable);
			if (start_response.has_member ("error")) {
				yield notify_pair_verify_failed (cancellable);
				return null;
			}
			uint8[] raw_device_pubkey = start_response.read_member ("public-key").get_data_value ().get_data ();
			start_response.end_member ();
			var device_pubkey = new Key.from_raw_public_key (X25519, null, raw_device_pubkey);

			Bytes shared_key = derive_shared_key (host_keypair, device_pubkey);

			Bytes operation_key = derive_chacha_key (shared_key,
				"Pair-Verify-Encrypt-Info",
				"Pair-Verify-Encrypt-Salt");

			var cipher = new ChaCha20Poly1305 (operation_key);

			// TODO: Verify signature using peer's public key.
			/* var start_inner_response = */ new VariantReader (PairingParamsParser.parse (cipher.decrypt (
				new Bytes.static ("\x00\x00\x00\x00PV-Msg02".data[:12]),
				start_response.read_member ("encrypted-data").get_data_value ())));

			unowned string host_identifier = store.self_identity.identifier;

			var message = new ByteArray.sized (100);
			message.append (raw_host_pubkey);
			message.append (host_identifier.data);
			message.append (raw_device_pubkey);
			Bytes signature = compute_message_signature (ByteArray.free_to_bytes ((owned) message), store.self_identity.key);

			Bytes inner_params = new PairingParamsBuilder ()
				.add_identifier (host_identifier)
				.add_signature (signature)
				.build ();

			Bytes outer_params = new PairingParamsBuilder ()
				.add_state (3)
				.add_encrypted_data (
					cipher.encrypt (
						new Bytes.static ("\x00\x00\x00\x00PV-Msg03".data[:12]),
						inner_params))
				.build ();

			Bytes finish_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("verifyManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (false)
					.set_member_name ("data")
					.add_data_value (outer_params)
				.end_dictionary ()
				.build ();

			ObjectReader finish_response = yield request_pairing_data (finish_payload, cancellable);
			if (finish_response.has_member ("error")) {
				yield notify_pair_verify_failed (cancellable);
				return null;
			}

			return shared_key;
		}

		private async void notify_pair_verify_failed (Cancellable? cancellable) throws Error, IOError {
			yield post_plain (transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("event")
					.begin_dictionary ()
						.set_member_name ("_0")
						.begin_dictionary ()
							.set_member_name ("pairVerifyFailed")
							.begin_dictionary ()
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build (), cancellable);
		}

		private async Bytes setup_manual_pairing (Cancellable? cancellable) throws Error, IOError {
			Bytes start_params = new PairingParamsBuilder ()
				.add_method (0)
				.add_state (1)
				.build ();

			Bytes start_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("setupManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (true)
					.set_member_name ("sendingHost")
					.add_string_value (Environment.get_host_name ())
					.set_member_name ("data")
					.add_data_value (start_params)
				.end_dictionary ()
				.build ();

			var start_response = yield request_pairing_data (start_payload, cancellable);
			if (start_response.has_member ("retry-delay")) {
				uint16 retry_delay = start_response.read_member ("retry-delay").get_uint16_value ();
				throw new Error.INVALID_OPERATION ("Rate limit exceeded, try again in %u seconds", retry_delay);
			}

			Bytes remote_pubkey = start_response.read_member ("public-key").get_data_value ();
			start_response.end_member ();

			Bytes salt = start_response.read_member ("salt").get_data_value ();
			start_response.end_member ();

			var srp_session = new SRPClientSession ("Pair-Setup", "000000");
			srp_session.process (remote_pubkey, salt);
			Bytes shared_key = srp_session.key;

			Bytes verify_params = new PairingParamsBuilder ()
				.add_state (3)
				.add_raw_public_key (srp_session.public_key)
				.add_proof (srp_session.key_proof)
				.build ();

			Bytes verify_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("setupManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (false)
					.set_member_name ("sendingHost")
					.add_string_value (Environment.get_host_name ())
					.set_member_name ("data")
					.add_data_value (verify_params)
				.end_dictionary ()
				.build ();

			var verify_response = yield request_pairing_data (verify_payload, cancellable);
			Bytes remote_proof = verify_response.read_member ("proof").get_data_value ();

			srp_session.verify_proof (remote_proof);

			Bytes operation_key = derive_chacha_key (shared_key,
				"Pair-Setup-Encrypt-Info",
				"Pair-Setup-Encrypt-Salt");

			var cipher = new ChaCha20Poly1305 (operation_key);

			Bytes signing_key = derive_chacha_key (shared_key,
				"Pair-Setup-Controller-Sign-Info",
				"Pair-Setup-Controller-Sign-Salt");

			unowned PairingIdentity self_identity = store.self_identity;
			Bytes self_identity_pubkey = get_raw_public_key (self_identity.key);

			var message = new ByteArray.sized (100);
			message.append (signing_key.get_data ());
			message.append (self_identity.identifier.data);
			message.append (self_identity_pubkey.get_data ());
			Bytes signature = compute_message_signature (ByteArray.free_to_bytes ((owned) message), self_identity.key);

			Bytes self_info = new OpackBuilder ()
				.begin_dictionary ()
					.set_member_name ("name")
					.add_string_value (Environment.get_host_name ())
					.set_member_name ("accountID")
					.add_string_value (self_identity.identifier)
					.set_member_name ("remotepairing_serial_number")
					.add_string_value ("AAAAAAAAAAAA")
					.set_member_name ("altIRK")
					.add_data_value (self_identity.irk)
					.set_member_name ("model")
					.add_string_value ("computer-model")
					.set_member_name ("mac")
					.add_data_value (new Bytes ({ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }))
					.set_member_name ("btAddr")
					.add_string_value ("11:22:33:44:55:66")
				.end_dictionary ()
				.build ();

			Bytes inner_params = new PairingParamsBuilder ()
				.add_identifier (self_identity.identifier)
				.add_raw_public_key (self_identity_pubkey)
				.add_signature (signature)
				.add_info (self_info)
				.build ();

			Bytes outer_params = new PairingParamsBuilder ()
				.add_state (5)
				.add_encrypted_data (
					cipher.encrypt (
						new Bytes.static ("\x00\x00\x00\x00PS-Msg05".data[:12]),
						inner_params))
				.build ();

			Bytes finish_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("setupManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (false)
					.set_member_name ("sendingHost")
					.add_string_value (Environment.get_host_name ())
					.set_member_name ("data")
					.add_data_value (outer_params)
				.end_dictionary ()
				.build ();

			var outer_finish_response = yield request_pairing_data (finish_payload, cancellable);
			var inner_finish_response = new VariantReader (PairingParamsParser.parse (
				cipher.decrypt (new Bytes.static ("\x00\x00\x00\x00PS-Msg06".data[:12]),
					outer_finish_response.read_member ("encrypted-data").get_data_value ())));

			string peer_identifier = inner_finish_response.read_member ("identifier").get_string_value ();
			inner_finish_response.end_member ();
			Bytes peer_pubkey = inner_finish_response.read_member ("public-key").get_data_value ();
			inner_finish_response.end_member ();
			Bytes peer_info = inner_finish_response.read_member ("info").get_data_value ();
			inner_finish_response.end_member ();
			store.add_peer (peer_identifier, peer_pubkey, peer_info);

			return shared_key;
		}

		private async ObjectReader request_pairing_data (Bytes payload, Cancellable? cancellable) throws Error, IOError {
			Bytes wrapper = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("event")
					.begin_dictionary ()
						.set_member_name ("_0")
						.begin_dictionary ()
							.set_member_name ("pairingData")
							.begin_dictionary ()
								.set_member_name ("_0")
								.add_raw_value (payload)
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();

			ObjectReader response = yield request_plain (wrapper, cancellable);

			response
				.read_member ("event")
				.read_member ("_0");

			if (response.has_member ("pairingRejectedWithError")) {
				string description = response
					.read_member ("pairingRejectedWithError")
					.read_member ("wrappedError")
					.read_member ("userInfo")
					.read_member ("NSLocalizedDescription")
					.get_string_value ();
				throw new Error.PROTOCOL ("%s", description);
			}

			Bytes raw_data = response
				.read_member ("pairingData")
				.read_member ("_0")
				.read_member ("data")
				.get_data_value ();
			Variant data = PairingParamsParser.parse (raw_data);
			return new VariantReader (data);
		}

		private async ObjectReader request_plain (Bytes payload, Cancellable? cancellable) throws Error, IOError {
			uint64 seqno = next_control_sequence_number++;
			var promise = new Promise<ObjectReader> ();
			requests[seqno] = promise;

			try {
				yield post_plain_with_sequence_number (seqno, payload, cancellable);
			} catch (GLib.Error e) {
				if (requests.unset (seqno))
					promise.reject (e);
			}

			ObjectReader response = yield promise.future.wait_async (cancellable);

			return response
				.read_member ("plain")
				.read_member ("_0");
		}

		private async void post_plain (Bytes payload, Cancellable? cancellable) throws Error, IOError {
			uint64 seqno = next_control_sequence_number++;
			yield post_plain_with_sequence_number (seqno, payload, cancellable);
		}

		private async void post_plain_with_sequence_number (uint64 seqno, Bytes payload, Cancellable? cancellable)
				throws Error, IOError {
			transport.post (transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("sequenceNumber")
					.add_uint64_value (seqno)
					.set_member_name ("originatedBy")
					.add_string_value ("host")
					.set_member_name ("message")
					.begin_dictionary ()
						.set_member_name ("plain")
						.begin_dictionary ()
							.set_member_name ("_0")
							.add_raw_value (payload)
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ());
		}

		private async string request_encrypted (string json, Cancellable? cancellable) throws Error, IOError {
			uint64 seqno = next_control_sequence_number++;
			var promise = new Promise<ObjectReader> ();
			requests[seqno] = promise;

			Bytes iv = new BufferBuilder (LITTLE_ENDIAN)
				.append_uint64 (next_encrypted_sequence_number++)
				.append_uint32 (0)
				.build ();

			Bytes raw_request = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("sequenceNumber")
					.add_uint64_value (seqno)
					.set_member_name ("originatedBy")
					.add_string_value ("host")
					.set_member_name ("message")
					.begin_dictionary ()
						.set_member_name ("streamEncrypted")
						.begin_dictionary ()
							.set_member_name ("_0")
							.add_data_value (client_cipher.encrypt (iv, new Bytes.static (json.data)))
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();

			transport.post (raw_request);

			ObjectReader response = yield promise.future.wait_async (cancellable);

			Bytes encrypted_response = response
				.read_member ("streamEncrypted")
				.read_member ("_0")
				.get_data_value ();

			Bytes decrypted_response = server_cipher.decrypt (iv, encrypted_response);

			unowned string s = (string) decrypted_response.get_data ();
			if (!s.validate ((ssize_t) decrypted_response.get_size ()))
				throw new Error.PROTOCOL ("Invalid UTF-8");

			return s;
		}

		private void on_close (Error? error) {
			var e = (error != null)
				? error
				: new Error.TRANSPORT ("Connection closed while waiting for response");
			foreach (Promise<ObjectReader> promise in requests.values)
				promise.reject (e);
			requests.clear ();
		}

		private void on_message (ObjectReader reader) {
			try {
				string origin = reader.read_member ("originatedBy").get_string_value ();
				if (origin != "device")
					return;
				reader.end_member ();

				uint64 seqno = reader.read_member ("sequenceNumber").get_uint64_value ();
				reader.end_member ();

				reader.read_member ("message");

				Promise<ObjectReader> promise;
				if (!requests.unset (seqno, out promise))
					return;

				promise.resolve (reader);
			} catch (Error e) {
			}
		}

		private static uint8[] key_to_der (Key key) {
			var sink = new BasicIO (BasicIOMethod.memory ());
			key.to_der (sink);
			unowned uint8[] der_data = get_basic_io_content (sink);
			uint8[] der_data_owned = der_data;
			return der_data_owned;
		}

		private static Key key_from_der (uint8[] der) throws Error {
			var source = new BasicIO.from_static_memory_buffer (der);
			Key? key = new Key.from_der (source);
			if (key == null)
				throw new Error.PROTOCOL ("Invalid key");
			return key;
		}

		private static unowned uint8[] get_basic_io_content (BasicIO bio) {
			unowned uint8[] data;
			long n = bio.get_mem_data (out data);
			data.length = (int) n;
			return data;
		}

		private static Bytes derive_shared_key (Key local_keypair, Key remote_pubkey) {
			var ctx = new KeyContext.for_key (local_keypair);
			ctx.derive_init ();
			ctx.derive_set_peer (remote_pubkey);

			size_t size = 0;
			ctx.derive (null, ref size);

			var shared_key = new uint8[size];
			ctx.derive (shared_key, ref size);

			return new Bytes.take ((owned) shared_key);
		}

		private static Bytes derive_chacha_key (Bytes shared_key, string info, string? salt = null) {
			var kdf = KeyDerivationFunction.fetch (null, KeyDerivationAlgorithm.HKDF);

			var kdf_ctx = new KeyDerivationContext (kdf);

			size_t return_size = OpenSSL.ParamReturnSize.UNMODIFIED;

			OpenSSL.Param kdf_params[] = {
				{ KeyDerivationParameter.DIGEST, UTF8_STRING, OpenSSL.ShortName.sha512.data, return_size },
				{ KeyDerivationParameter.KEY, OCTET_STRING, shared_key.get_data (), return_size },
				{ KeyDerivationParameter.INFO, OCTET_STRING, info.data, return_size },
				{ (salt != null) ? KeyDerivationParameter.SALT : null, OCTET_STRING, (salt != null) ? salt.data : null,
					return_size },
				{ null, INTEGER, null, return_size },
			};

			var derived_key = new uint8[32];
			kdf_ctx.derive (derived_key, kdf_params);

			return new Bytes.take ((owned) derived_key);
		}

		private static Bytes compute_message_signature (Bytes message, Key key) {
			var ctx = new MessageDigestContext ();
			ctx.digest_sign_init (null, null, null, key);

			unowned uint8[] data = message.get_data ();

			size_t size = 0;
			ctx.digest_sign (null, ref size, data);

			var signature = new uint8[size];
			ctx.digest_sign (signature, ref size, data);

			return new Bytes.take ((owned) signature);
		}

		private class ChaCha20Poly1305 {
			private Bytes key;

			private Cipher cipher = Cipher.fetch (null, OpenSSL.ShortName.chacha20_poly1305);
			private CipherContext? cached_ctx;

			private const size_t TAG_SIZE = 16;

			public ChaCha20Poly1305 (Bytes key) {
				this.key = key;
			}

			public Bytes encrypt (Bytes iv, Bytes message) {
				size_t cleartext_size = message.get_size ();
				var buf = new uint8[cleartext_size + TAG_SIZE];

				unowned CipherContext ctx = get_context ();
				cached_ctx.encrypt_init (cipher, key.get_data (), iv.get_data ());

				int size = buf.length;
				ctx.encrypt_update (buf, ref size, message.get_data ());

				int extra_size = buf.length - size;
				ctx.encrypt_final (buf[size:], ref extra_size);
				assert (extra_size == 0);

				ctx.ctrl (AEAD_GET_TAG, (int) TAG_SIZE, (void *) buf[size:]);

				return new Bytes.take ((owned) buf);
			}

			public Bytes decrypt (Bytes iv, Bytes message) throws Error {
				size_t message_size = message.get_size ();
				if (message_size < 1 + TAG_SIZE)
					throw new Error.PROTOCOL ("Encrypted message is too short");
				unowned uint8[] message_data = message.get_data ();

				var buf = new uint8[message_size];

				unowned CipherContext ctx = get_context ();
				cached_ctx.decrypt_init (cipher, key.get_data (), iv.get_data ());

				int size = (int) message_size;
				int res = ctx.decrypt_update (buf, ref size, message_data);
				if (res != 1)
					throw new Error.PROTOCOL ("Failed to decrypt: %d", res);

				int extra_size = buf.length - size;
				res = ctx.decrypt_final (buf[size:], ref extra_size);
				if (res != 1)
					throw new Error.PROTOCOL ("Failed to decrypt: %d", res);
				assert (extra_size == 0);

				size_t cleartext_size = message_size - TAG_SIZE;
				buf[cleartext_size] = 0;
				buf.length = (int) cleartext_size;

				return new Bytes.take ((owned) buf);
			}

			private unowned CipherContext get_context () {
				if (cached_ctx == null)
					cached_ctx = new CipherContext ();
				else
					cached_ctx.reset ();
				return cached_ctx;
			}
		}

		private class SRPClientSession {
			public Bytes public_key {
				owned get {
					var buf = new uint8[local_pubkey.num_bytes ()];
					local_pubkey.to_big_endian (buf);
					return new Bytes.take ((owned) buf);
				}
			}

			public Bytes key {
				get {
					return _key;
				}
			}

			public Bytes key_proof {
				get {
					return _key_proof;
				}
			}

			private string username;
			private string password;

			private BigNumber prime = BigNumber.get_rfc3526_prime_3072 ();
			private BigNumber generator;
			private BigNumber multiplier;

			private BigNumber local_privkey;
			private BigNumber local_pubkey;

			private BigNumber? remote_pubkey;
			private Bytes? salt;

			private BigNumber? password_hash;
			private BigNumber? password_verifier;

			private BigNumber? common_secret;
			private BigNumber? premaster_secret;
			private Bytes? _key;
			private Bytes? _key_proof;
			private Bytes? _key_proof_hash;

			private BigNumberContext bn_ctx = new BigNumberContext.secure ();

			public SRPClientSession (string username, string password) {
				this.username = username;
				this.password = password;

				uint8 raw_gen = 5;
				generator = new BigNumber.from_native ((uint8[]) &raw_gen);
				multiplier = new HashBuilder ()
					.add_number_padded (prime)
					.add_number_padded (generator)
					.build_number ();

				uint8 raw_local_privkey[128];
				Rng.generate (raw_local_privkey);
				local_privkey = new BigNumber.from_big_endian (raw_local_privkey);

				local_pubkey = new BigNumber ();
				BigNumber.mod_exp (local_pubkey, generator, local_privkey, prime, bn_ctx);
			}

			public void process (Bytes raw_remote_pubkey, Bytes salt) throws Error {
				remote_pubkey = new BigNumber.from_big_endian (raw_remote_pubkey.get_data ());
				var rem = new BigNumber ();
				BigNumber.mod (rem, remote_pubkey, prime, bn_ctx);
				if (rem.is_zero ())
					throw new Error.INVALID_ARGUMENT ("Malformed remote public key");

				this.salt = salt;

				password_hash = compute_password_hash (salt);
				password_verifier = compute_password_verifier (password_hash);

				common_secret = compute_common_secret (remote_pubkey);
				premaster_secret = compute_premaster_secret (common_secret, remote_pubkey, password_hash,
					password_verifier);
				_key = compute_session_key (premaster_secret);
				_key_proof = compute_session_key_proof (_key, remote_pubkey, salt);
				_key_proof_hash = compute_session_key_proof_hash (_key_proof, _key);
			}

			public void verify_proof (Bytes proof) throws Error {
				size_t size = proof.get_size ();
				if (size != _key_proof_hash.get_size ())
					throw new Error.INVALID_ARGUMENT ("Invalid proof size");

				if (Crypto.memcmp (proof.get_data (), _key_proof_hash.get_data (), size) != 0)
					throw new Error.INVALID_ARGUMENT ("Invalid proof");
			}

			private BigNumber compute_password_hash (Bytes salt) {
				return new HashBuilder ()
					.add_bytes (salt)
					.add_bytes (new HashBuilder ()
						.add_string (username)
						.add_string (":")
						.add_string (password)
						.build_digest ())
					.build_number ();
			}

			private BigNumber compute_password_verifier (BigNumber password_hash) {
				var verifier = new BigNumber ();
				BigNumber.mod_exp (verifier, generator, password_hash, prime, bn_ctx);
				return verifier;
			}

			private BigNumber compute_common_secret (BigNumber remote_pubkey) {
				return new HashBuilder ()
					.add_number_padded (local_pubkey)
					.add_number_padded (remote_pubkey)
					.build_number ();
			}

			private BigNumber compute_premaster_secret (BigNumber common_secret, BigNumber remote_pubkey,
					BigNumber password_hash, BigNumber password_verifier) {
				var val = new BigNumber ();

				BigNumber.mul (val, multiplier, password_verifier, bn_ctx
```