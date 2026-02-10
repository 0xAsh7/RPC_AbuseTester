# **Technical Analysis of Remote Procedure Call Abuse in Blockchain Infrastructure**

## **1\. RPC Interface Mechanics**

Remote Procedure Call (RPC) interfaces in blockchain infrastructure serve as the primary gateway for external applications to interact with the underlying blockchain state machine.1 These interfaces are implemented as application-layer protocols that abstract the complexity of peer-to-peer (P2P) networking, allowing clients to execute functions on a remote node as if they were local procedure calls.3 The execution of RPC methods involves specific transport protocols, serialization formats, and internal service registration flows within the blockchain client software.6

### **1.1 Transport Layer Implementations**

Blockchain nodes typically expose RPC services over three primary transport layers: Inter-Process Communication (IPC), Hypertext Transfer Protocol (HTTP), and WebSockets (WS).6

| Transport Protocol | Mechanism | Scope | Characteristics |
| :---- | :---- | :---- | :---- |
| IPC | Unix domain sockets (Linux/macOS) or named pipes (Windows) 6 | Local only | High security; avoids network stack; default access to all namespaces 6 |
| HTTP | Stateless request-response over TCP 7 | Local/Network | Ubiquitous; high overhead for high-frequency queries; lacks native pub/sub 7 |
| WebSockets | Stateful bidirectional stream over TCP 6 | Local/Network | Persistent connections; supports subscriptions/event streaming; lower per-message overhead 6 |

In high-performance architectures such as Solana, gRPC (Google Remote Procedure Call) is employed for streaming high-throughput data using Protobuf serialization over HTTP/2, although it is not natively supported by standard Web3 clients like Ethers.js or MetaMask.8

### **1.2 Serialization and Protocol Specifications**

Blockchain RPC systems predominantly utilize the JSON-RPC 2.0 specification.4 This protocol defines a lightweight, transport-agnostic data-interchange format.10 A standard JSON-RPC request consists of four mandatory fields: jsonrpc (version string "2.0"), method (procedure name), params (array or object of arguments), and id (unique client-generated identifier).6

The internal execution flow of a request involves marshalling and unmarshalling.4 The client stub marshals the parameters into a standard JSON format for network transmission.4 Upon receipt, the server-side dispatcher—often referred to as a skeleton—unmarshals the parameters into native data types and routes the call to the appropriate internal procedure.4

### **1.3 Service Registration and Dispatching**

Blockchain clients like Go-Ethereum (Geth) implement a namespace-based service registration system to manage method access.6 During node initialization, functional modules are registered as "services" within the RPC server.15

In Geth, the rpc.API struct defines the registration parameters 15:

* **Namespace:** A prefix grouping related methods (e.g., eth, net, web3, admin, debug, personal).6  
* **Service:** The receiver instance that implements the actual methods.15  
* **Public:** A flag indicating whether the API is intended for public consumption over network transports.15

For a method to be eligible for registration and remote execution, it must be exported (capitalized in Go), and its return values must follow specific conventions: it may return zero, one (response or error), or two (response and error) values.15 Subscription-based methods, utilized over WebSockets, must return an rpc.Subscription and an error.15

## **2\. Network Exposure Process**

The transition of a blockchain node from a local-only instance to a network-exposed service is governed by interface binding configurations and infrastructure-level network policies.16

### **2.1 Interface Binding and Host Configuration**

By default, blockchain clients bind their RPC services to the local loopback interface (127.0.0.1 or localhost).7 Network exposure is achieved by modifying the listening address to a public or shared interface.16

| Client Configuration | Flag | Default Binding | Exposure Binding |
| :---- | :---- | :---- | :---- |
| Geth HTTP Address | \--http.addr | localhost 16 | 0.0.0.0 16 |
| Geth WS Address | \--ws.addr | localhost 16 | 0.0.0.0 7 |
| Besu HTTP Port | \--rpc-http-port | 8545 19 | User-defined 19 |
| Tendermint Listen Address | \--rpc.laddr | tcp://127.0.0.1:26657 | tcp://0.0.0.0:26657 21 |
| Solana RPC Port | \--rpc-port | 8899 11 | User-defined 23 |

Binding to 0.0.0.0 instructs the node to listen on all available network interfaces, making the RPC port accessible from other containers, local networks, or the public internet, depending on host firewall settings.16

### **2.2 Container and Infrastructure Mapping**

In containerized environments (e.g., Docker, Kubernetes), network exposure requires mapping internal container ports to host ports.16 For example, a Geth node running in a Docker container must have port 8545 explicitly exposed to the host to accept external JSON-RPC traffic.16

In cloud deployments such as AWS, exposure is controlled through Security Groups and Network Access Control Lists (NACLs).19 Nodes may be placed behind load balancers or ingress controllers like Ambassador.19 Hyperledger Besu specifically supports UPnP (Universal Plug and Play) to automate port forwarding in environments with NAT isolation.19

### **2.3 Network Plane Configuration and NAT**

The visibility of the node within the p2p network is often decoupled from its RPC visibility.23 For instance, Solana nodes use the \--private-rpc flag to prevent the RPC port from being advertised in the gossip network, while still allowing the port to accept direct TCP connections from authorized clients.23 Nodes advertising external addresses for their enode or listenAddr use methods like \--nat-method to handle network address translation.26

## **3\. RPC Discovery Process**

Discovery is the phase in which attackers identify active blockchain RPC endpoints through active scanning, fingerprinting, and passive data collection.14

### **3.1 Active Scanning and Port Sweep**

Attackers utilize network reconnaissance tools to sweep IPv4 and IPv6 address spaces for open ports traditionally associated with blockchain RPC services.14

| Protocol | Standard RPC Port | Standard WS Port |
| :---- | :---- | :---- |
| Ethereum (Geth/Besu) | 8545 16 | 8546 16 |
| Tendermint (CometBFT) | 26657 21 | 26657 (via /websocket) 21 |
| Solana | 8899 11 | 8900 11 |

Advanced scanning involves identifying high ports used dynamically by RPC services, particularly the RPC Endpoint Mapper (TCP 135\) on Windows-based infrastructure.14

### **3.2 Fingerprinting via Method Probing**

Verification of a blockchain node's identity is achieved through fingerprinting, which involves sending specific JSON-RPC requests and analyzing the response format and content.27

The eth\_blockNumber method is the primary fingerprint for EVM-compatible nodes.6 A request to an open port: {"jsonrpc":"2.0", "method":"eth\_blockNumber", "params":, "id":1} If the response contains a hexadecimal result like {"id":1, "jsonrpc":"2.0", "result":"0x109238e"}, it confirms the presence of an active Ethereum RPC server.6

Secondary fingerprinting uses methods like web3\_clientVersion or net\_version to determine the specific client implementation (e.g., Geth, Besu, Erigon, Nethermind) and the underlying network (Mainnet vs. Testnet).30 Tendermint nodes are fingerprinted using the /status or /net\_info endpoints, which return detailed JSON objects regarding the node's moniker, network ID, and peer connections.21

### **3.3 Passive Discovery and Global Indexing**

Attackers leverage passive reconnaissance by querying global internet scanners such as Shodan, Censys, and ThreatNG.14 These platforms index banners and response payloads for internet-facing services.14 Queries for common JSON-RPC error codes (e.g., \-32601) or default response strings allow for the identification of vulnerable or misconfigured nodes without initiating direct scans that might trigger Intrusion Detection Systems (IDS).14

## **4\. RPC Capability Enumeration**

Enumeration is the systematic process of determining which API namespaces and specific methods are enabled on a target node.1 This determines the attack surface available to the adversary.

### **4.1 Namespace and Method Availability**

Blockchain nodes allow operators to whitelist specific namespaces over different transports.6 Enumeration attempts to call methods from various namespaces to identify the configuration.6

| Namespace | Functions | Risk Context |
| :---- | :---- | :---- |
| eth | Balance queries, contract reads, transaction submission 10 | Default; allows state monitoring and transaction relay 10 |
| admin | Peer management, datadir access, network control 16 | High risk; allows network manipulation and node shutdown 36 |
| debug | Transaction tracing, re-execution of blocks 16 | High risk; causes resource exhaustion and reveals internal state 31 |
| personal | Account creation, management, and unlocking 16 | Critical risk; allows unauthorized signing if accounts are unlocked 18 |
| miner | Control of block production and mining parameters 16 | Moderate risk; allows disruption of validation rewards 38 |

### **4.2 Probing for Unsafe APIs**

Attackers specifically target "unsafe" methods that modify node behavior or reveal sensitive data.21 In Tendermint-based systems, enumeration targets methods like /dial\_seeds and /unsafe\_flush\_mempool.21 Successful execution of these calls confirms that the node is running with the unsafe \= true configuration in the config.toml file.39

### **4.3 Error Handling and Logic Inference**

The RPC server's response to unauthorized or invalid calls provides metadata about its internal state.7

* **Error Code \-32601 (Method not found):** Indicates the namespace or method is not registered or not whitelisted for the current transport.7  
* **Error Code \-32600 (Invalid Request):** Indicates the JSON structure is malformed, suggesting a lack of robust input validation.12  
* **405 Method Not Allowed:** Occurs when attempting WebSocket-only methods (like eth\_subscribe) over an HTTP transport.6

## **5\. RPC Wallet Interaction Flow**

Abuse of wallet-related RPC methods targets the lifecycle of account management and transaction signing to facilitate the theft of assets.18

### **5.1 Account Unlocking Mechanism**

The personal\_unlockAccount method is the primary vector for unauthorized transaction signing.18 When a node operator unlocks an account via RPC, the node decrypts the associated private key and stores it in volatile memory for a specified duration (the duration parameter).18 During this interval, the node acts as a "hot wallet".18

Mechanistically, any subsequent call to eth\_sendTransaction that specifies the unlocked address as the from parameter will be automatically signed by the node's internal AccountManager without requiring further credentials.10 Attackers continuously poll nodes for unlocked accounts by attempting small eth\_sendTransaction calls or by monitoring the node's behavior during known maintenance windows.18

### **5.2 Transaction Drafting and Submission**

An attacker initiates a fund transfer by constructing a JSON-RPC payload for eth\_sendTransaction.10

| Transaction Field | Description |
| :---- | :---- |
| from | The target address identified as potentially unlocked 10 |
| to | The attacker's destination address 10 |
| value | The amount to be transferred, usually in Wei (hexadecimal) 10 |
| gas | The maximum gas permitted for the execution 10 |
| data | (Optional) ABI-encoded data for contract interactions 10 |

Once submitted, the node's RPC server passes the transaction to the txpool (mempool), where it is validated and gossiped to peers.36

### **5.3 External Signing and Web3Signer Relay**

In hardened environments, Besu nodes utilize Web3Signer to decouple key storage from the RPC node.35 The flow for an RPC-triggered transaction in this architecture is:

1. **RPC Request:** The node receives an eth\_sendTransaction request via HTTP or WS.35  
2. **Relay:** The node identifies that it does not hold the keys and relays the signing request to the configured Web3Signer endpoint.35  
3. **Authentication:** Web3Signer validates the request using a JWT token or mutual TLS.35  
4. **HSM Interaction:** Web3Signer interacts with an HSM or secure enclave (e.g., Nitro Enclaves) to sign the transaction payload.35  
5. **Broadcast:** The signed transaction is returned to the node, which then broadcasts it to the network.35

Abuse occurs if the node's relay mechanism or the Web3Signer's authentication is bypassed, allowing attackers to trigger signatures remotely.47

## **6\. Validator / Miner RPC Interaction**

Validator and miner RPC interactions focus on the control plane of the node, governing block production and consensus participation.16

### **6.1 The Engine API and Consensus Bridge**

Post-Merge Ethereum nodes utilize the Engine API as a bridge between the Consensus Client (Beacon Node) and the Execution Client (Geth/Besu).6 This API is typically exposed on port 8551 and requires a shared secret (JWT) for authentication.6

| Engine API Method | Functional Role |
| :---- | :---- |
| engine\_newPayloadV1 | Submits a new execution payload to the execution client for validation 30 |
| engine\_forkchoiceUpdatedV1 | Updates the execution client on the current head of the consensus chain 30 |
| engine\_getPayloadV1 | Retrieves a built execution payload for block proposal 30 |

Abuse of this interface allows an attacker to manipulate the execution client's view of the canonical chain, forcing it to follow a malicious fork or produce invalid blocks.30

### **6.2 Miner Namespace and Work Submission**

In Proof of Work (PoW) or Proof of Authority (PoA) systems like Hyperledger Besu, the miner namespace controls the block production engine.7 Methods like miner\_start and miner\_stop enable or disable block production.36 In PoW contexts, eth\_getWork provides the header-hash, seed-hash, and boundary condition to external mining software.16 Attackers targeting these RPCs can disrupt the node's revenue stream or prevent it from validating transactions.49

### **6.3 Tendermint Validator Set Manipulation**

Tendermint (CometBFT) nodes expose validator information via the /validators RPC endpoint.21 While this is primarily a read-only method, it allows attackers to monitor the voting power and proposer priority of specific nodes.50 This information is used to coordinate Distributed Denial of Service (DDoS) attacks against the current block proposer (leader) to cause network stalls.23

## **7\. Abuse Execution Flow (Step-by-Step)**

The end-to-end execution of blockchain RPC abuse follows a mechanistic sequence from initial exposure to final exploitation.

1. **Network Exposure:** A node is started with flags like \--http.addr 0.0.0.0 or \--rpcaddr 0.0.0.0, binding the RPC server to all interfaces.16  
2. **Discovery:** An attacker identifies the node by scanning for port 8545 or 26657 across public IP ranges.14  
3. **Identity Verification:** The attacker sends an eth\_blockNumber request. The node returns the current chain height in hexadecimal, confirming it is an Ethereum-compatible RPC service.27  
4. **Namespace Mapping:** The attacker probes for enabled APIs using methods like web3\_clientVersion. If the response indicates an outdated client, the attacker prioritizes known CVEs for that version.30  
5. **Account Listing:** The attacker calls eth\_accounts. The node returns a list of addresses managed by the local keystore.10  
6. **Unlocking Probe:** The attacker monitors the node for personal\_unlockAccount calls. If the node is poorly configured, the attacker may attempt to brute-force the password via RPC.18  
7. **Balance Monitoring:** The attacker polls eth\_getBalance for the discovered addresses. If a balance is present, the address is marked for immediate exploitation.10  
8. **Transaction Injection:** Once an account is unlocked, the attacker sends an eth\_sendTransaction request, transferring the entire balance to their own address.10  
9. **Resource Exhaustion (Optional):** The attacker floods the node with debug\_traceBlock calls, saturating the CPU and causing the node to fall out of consensus sync.31  
10. **Persistence and Lateral Movement:** If the admin namespace is enabled, the attacker uses admin\_addPeer to connect the node to a cluster of malicious peers, enabling eclipse attacks.36

## **8\. Data and Control Plane Separation**

Blockchain nodes operate across two distinct planes: the Control Plane, responsible for consensus and network topology, and the Data Plane (or Execution Plane), responsible for transaction execution and state storage.52

### **8.1 Monolithic Architecture Risks**

In standard clients like Geth, the Control and Data planes share the same physical hardware resources (CPU, RAM, Disk I/O).44 This sharing creates a "noisy neighbor" effect where RPC-driven data plane activity can compromise control plane stability.48

| Resource Contention | Data Plane Activity | Control Plane Consequence |
| :---- | :---- | :---- |
| CPU | Heavy eth\_call or debug\_trace 31 | Late block signing; missed slots 23 |
| RAM | Caching historical state for RPC queries 8 | Out-of-memory (OOM) kills of consensus client 56 |
| Disk I/O | Frequent historical state lookups 2 | Slow block validation and database writes 23 |

### **8.2 Decoupled Execution (SepChain and Rollups)**

Research into "SepChain" and modular architectures demonstrates that separating the ordering blockchain (Control Plane) from multiple execution blockchains (Data Plane) improves throughput by isolating transaction processing from consensus.55 However, this separation introduces new RPC-based attack vectors where an compromised RPC endpoint can feed the execution plane a different state than the consensus plane, leading to local forks.47

### **8.3 Infrastructure-Level Separation**

Enterprise-grade deployments use network-level separation to isolate the planes.52

* **Validator Node:** Runs with \--no-voting false and RPC disabled or restricted to a private VPN.23  
* **RPC Node:** Runs with \--no-voting true and \--full-rpc-api, focused entirely on serving client requests.23 This separation ensures that a DoS attack on the public RPC endpoint does not impact the validator's ability to participate in consensus.23

## **9\. Logging and Telemetry Behavior**

Logging and telemetry mechanisms provide the audit trail necessary to identify RPC abuse patterns and unauthorized access attempts.26

### **9.1 Client-Specific Logging Formats**

The internal logging behavior of blockchain clients varies by implementation and language.59

| Client | Technology | Logging Mechanism | Structured Format |
| :---- | :---- | :---- | :---- |
| Geth | Go | Native logger with \--log.json flag 59 | JSON 59 |
| Besu | Java | Log4j2 library 59 | Text (Standard) or XML/JSON (Configurable) 59 |
| Solana | Rust | env\_logger / tracing | Text / JSON |

Geth's verbosity settings allow for granular monitoring of the RPC module.60 Setting \--vmodule 'rpc=5' triggers the logging of every incoming JSON-RPC request, including the method name, parameter values, and client ID.60

### **9.2 Telemetry Indicators of Abuse**

Analysis of RPC telemetry reveals specific behavioral signatures associated with abuse:

* **Authentication Failures:** A high frequency of "rpc error: code \= Unauthenticated" or "401 Unauthorized" indicates failed JWT or API key attempts.35  
* **Namespace Probing:** Log entries showing repeated calls to non-existent or restricted methods like personal\_unlockAccount or admin\_nodeInfo.18  
* **Latency Spikes:** Histograms showing a shift in rpc\_request\_duration\_seconds for eth\_call suggest resource exhaustion attacks.8  
* **High Error-to-Request Ratio:** A spike in the otelcol\_exporter\_send\_failed metric suggests the node's telemetry exporter is being overwhelmed or blocked.61

### **9.3 Forensics and Chain of Custody**

On-chain forensic applications utilize RPC logs to establish a tamper-proof record of transactions.62 Every action within a forensic investigation—such as data preservation or evidence tracking—triggers a verifiable transaction via RPC.62 The node's Bloom.Index is used to accelerate searches for these log events, ensuring that the chain of custody remains auditable even in high-throughput environments.26

## **10\. RPC Security Testing Mechanics**

Security testing for RPC interfaces involves active probing and simulation to identify implementation flaws and misconfigurations.29

### **10.1 Static and Dynamic Analysis**

* **Static Analysis:** Frameworks like Slither are used to examine the smart contract source code that the RPC node will interact with, identifying logic errors that could be triggered via eth\_call.64  
* **Dynamic Analysis:** Tools like Manticore or Echidna perform symbolic execution and fuzzing.29 They generate random or malformed JSON-RPC payloads to test the node's resilience against parser-level DoS or memory corruption.29

### **10.2 Penetration Testing Phases**

The technical sequence of RPC penetration testing consists of five phases 64:

1. **Planning:** Defining the RPC endpoints and API versions in scope.64  
2. **Infrastructure Mapping:** Using tools like Nmap to identify firewall rules and load balancer configurations protecting the RPC.29  
3. **Vulnerability Scanning:** Running automated scanners like Mythril or custom RPC-specific suites to identify "low-hanging fruit" like open admin namespaces.29  
4. **Exploitation:** Attempting unauthorized signing or state manipulation based on discovered flaws.64  
5. **Remediation Testing:** Re-testing the endpoint after patches (e.g., enabling JWT) are applied.64

### **10.3 Testing for "Free" Execution Abuse**

Attackers exploit the fact that eth\_call simulations are "free" (do not consume on-chain gas) to execute complex, resource-intensive computations on the node.1 Testing for this involves sending increasingly complex contract calls to determine if the node implements a "soft cap" on gas for simulations.32 Failure to implement this cap allows for CPU exhaustion.1

## **11\. Audit Tool Operation**

Blockchain audit tools automate the identification of insecure RPC configurations and classify methods based on their potential impact.64

### **11.1 Black Box vs. Grey Box Methodologies**

* **Black Box Audit:** The audit team operates solely through public RPC interfaces without access to internal code or configuration files.65 Testing focuses on observable behaviors and response signatures.65  
* **Grey Box Audit:** Auditors have limited access to partial code or configuration files (e.g., config.toml, genesis.json).25 This allows for deeper assessment of the node's internal logic, such as the specific account indexing (--account-index) or ledger size limits (--limit-ledger-size).23

### **11.2 Automated Scanning Logic**

Automated RPC audit tools operate according to the following mechanistic sequence:

1. **Transport Detection:** The tool attempts to connect via HTTP (8545), WS (8546), and IPC.6  
2. **Namespace Brute-forcing:** The tool sends a request for a method in each known namespace (e.g., eth\_blockNumber, admin\_nodeInfo, personal\_listAccounts).10  
3. **Permission Mapping:** For each method, it records the response:  
   * 200 OK: Method is public and unauthenticated.36  
   * 401 Unauthorized: Method is protected but enabled.35  
   * Error \-32601: Method is not whitelisted or not supported by the client.7  
4. **CORS/Vhost Analysis:** The tool checks the Access-Control-Allow-Origin and Host header enforcement.16

### **11.3 Error Classification and Reporting**

Audit tools classify findings into a severity matrix based on the exploit potential of the exposed RPC method.66

| Severity | Definition | RPC Example |
| :---- | :---- | :---- |
| Critical | Impacts safe functioning or enables fund theft 66 | Unauthenticated personal or admin access 18 |
| Major | Logical errors leading to protocol control loss 66 | Exposed Engine API on port 8551 6 |
| Medium | Affects performance or reliability 66 | Unrestricted debug\_traceTransaction access 31 |
| Minor | Inefficient code or stylistic issues 66 | Missing rate limiting on read-only methods 41 |

## **12\. Mitigation Implementation Mechanics**

Securing a blockchain RPC interface requires the implementation of authentication, network isolation, and resource controls.35

### **12.1 Authentication and JWT Mechanics**

Enterprise clients use JSON Web Tokens (JWT) for stateless authentication.35

1. **Configuration:** The node is started with \--rpc-http-authentication-enabled.35  
2. **Provider Setup:** A JWT provider's public key file is specified via \--rpc-http-authentication-jwt-public-key-file.35  
3. **Token Processing:** When an RPC request arrives with a Bearer token, the node verifies the signature using the public key and confirms that the requested method is included in the permissions claim of the JWT.35

### **12.2 Network-Level Protections**

* **Vhost Filtering:** Geth uses the \--rpcvhosts flag to ensure the HTTP Host header matches a whitelist, mitigating DNS rebinding attacks where a malicious site uses a user's browser to send requests to localhost:8545.67  
* **CORS Hardening:** The \--rpccorsdomain flag is set to specific, trusted domains rather than the wildcard \*.16  
* **IP Whitelisting:** Firewall rules (iptables or cloud-based) restrict access to the RPC port to specific CIDR ranges (e.g., the backend server's IP).14

### **12.3 Resource Management and Quotas**

Managed RPC providers implement "Compute Units" (CUs) to normalize resource consumption across different methods.57

| Method | Resource Intensity | CU Multiplier |
| :---- | :---- | :---- |
| eth\_blockNumber | Low | 1x 68 |
| eth\_call | Moderate | 2x-5x 68 |
| debug\_traceBlockByHash | Extreme | 50x 68 |

This mechanism prevents a single user from overwhelming the shared node infrastructure by making resource-intensive calls.57

## **13\. Failure Modes**

Failure modes are the technical conditions under which RPC security controls break down, leading to infrastructure compromise or network penalties.42

### **13.1 Configuration Drift and Automation Failures**

Configuration drift occurs when the running state of the RPC infrastructure deviates from the intended version-controlled configuration.70

* **Mechanic:** A CI/CD pipeline deployment appears successful, but a ConfigMap key change is not propagated to the node's startup flags.71  
* **Result:** The node starts with default, insecure bindings (e.g., 8545 open without JWT), exposing the admin namespace unintentionally.71

### **13.2 Failover Race Conditions and Double-Signing**

In high-availability validator setups, RPC-based health checks govern the transition between primary and secondary nodes.42

1. **Failure:** The primary node's RPC endpoint becomes unresponsive.8  
2. **Trigger:** An automated failover script (e.g., Kubernetes liveness probe) fails and starts a standby validator.42  
3. **Conflict:** The primary node was not fully offline (only its RPC interface was down); both nodes now hold the same validator key and are signing blocks.42  
4. **Proof:** The network receives two different blocks signed for the same slot by the same identity.73  
5. **Slashing Execution:** A "whistleblower" node submits the conflicting signatures to the slashing program (e.g., at address S1ashing11111111111111111111111111111111111 on Solana).73 The offender's stake is immediately burned.46

### **13.3 Resource Exhaustion Cascades**

Resource exhaustion occurs when a flood of RPC requests consumes the hardware resources required for consensus.23

* **Mechanic:** An attacker identifies a "hot" account or contract and floods the node with eth\_getLogs requests with large block ranges.8  
* **Result:** The node's disk I/O saturates as it attempts to fetch historical data.23 The consensus client (e.g., Prysm or Lighthouse) misses the p2p "head" updates because the execution client is too busy serving RPC traffic.23 The node falls out of the validator set for downtime violations.46

### **13.4 Silent Data Loss in Telemetry**

A critical failure mode in monitoring is the authentication failure of telemetry exporters.61 If the OpenTelemetry collector fails to authenticate with the backend, RPC abuse logs are dropped silently.61 The node continues to function, but the security team has zero visibility into the ongoing attack.61 This is diagnosed by monitoring the otelcol\_exporter\_send\_failed metric or checking for "rpc error: code \= Unauthenticated" in the collector's internal logs.61

#### **Works cited**

1. What Is A Blockchain RPC Node \- Your Complete Guide \- Cyfrin, accessed February 10, 2026, [https://www.cyfrin.io/blog/blockchain-rpc-node-guide](https://www.cyfrin.io/blog/blockchain-rpc-node-guide)  
2. What is Remote Procedure Call (RPC)? Understanding its role in blockchain | CoinTracker, accessed February 10, 2026, [https://www.cointracker.io/learn/remote-procedure-call-rpc](https://www.cointracker.io/learn/remote-procedure-call-rpc)  
3. Introduction to RPC Programming \- IBM, accessed February 10, 2026, [https://www.ibm.com/docs/en/entirex/11.0.0?topic=programming-introduction-rpc](https://www.ibm.com/docs/en/entirex/11.0.0?topic=programming-introduction-rpc)  
4. Remote procedure call \- Wikipedia, accessed February 10, 2026, [https://en.wikipedia.org/wiki/Remote\_procedure\_call](https://en.wikipedia.org/wiki/Remote_procedure_call)  
5. An Introduction to Remote Procedural Call (RPC) Nodes in Blockchains \- DEV Community, accessed February 10, 2026, [https://dev.to/davidekete/an-introduction-to-remote-procedural-call-rpc-nodes-in-blockchain-p88](https://dev.to/davidekete/an-introduction-to-remote-procedural-call-rpc-nodes-in-blockchain-p88)  
6. JSON RPC-Server In Geth \- by Sushmit Sharma \- Medium, accessed February 10, 2026, [https://medium.com/@sushmitshrm/json-rpc-server-in-geth-9c14c86ca3e8](https://medium.com/@sushmitshrm/json-rpc-server-in-geth-9c14c86ca3e8)  
7. JSON-RPC Server | Go Ethereum \- GitHub Pages, accessed February 10, 2026, [https://ethereumpow.github.io/go-ethereum/docs/rpc/server](https://ethereumpow.github.io/go-ethereum/docs/rpc/server)  
8. What is Solana RPC: nodes, endpoints, and data access \- Triton Blog, accessed February 10, 2026, [https://blog.triton.one/what-is-solana-rpc-nodes-endpoints-and-data-access/](https://blog.triton.one/what-is-solana-rpc-nodes-endpoints-and-data-access/)  
9. RPC vs gRPC for Blockchain dApps Development \- dRPC, accessed February 10, 2026, [https://drpc.org/blog/rpc-vs-grpc/](https://drpc.org/blog/rpc-vs-grpc/)  
10. A Guide on Ethereum RPCs, Methods and Calls \- Blockchain Council, accessed February 10, 2026, [https://www.blockchain-council.org/blockchain/a-guide-on-ethereum-rpcs-methods-and-calls/](https://www.blockchain-council.org/blockchain/a-guide-on-ethereum-rpcs-methods-and-calls/)  
11. Solana RPC HTTP Methods, accessed February 10, 2026, [https://solana.com/docs/rpc/http](https://solana.com/docs/rpc/http)  
12. Tutorial: JSON-RPC Server \- Rolo documentation, accessed February 10, 2026, [https://rolo.localstack.cloud/tutorials/jsonrpc-server.html](https://rolo.localstack.cloud/tutorials/jsonrpc-server.html)  
13. Understanding Remote Procedure Calls (RPC) \- FireCompass, accessed February 10, 2026, [https://firecompass.com/understanding-remote-procedure-calls-rpc/](https://firecompass.com/understanding-remote-procedure-calls-rpc/)  
14. Remote Procedure Call (RPC) — ThreatNG Security \- External Attack Surface Management (EASM) \- Digital Risk Protection, accessed February 10, 2026, [https://www.threatngsecurity.com/glossary/rpc](https://www.threatngsecurity.com/glossary/rpc)  
15. rpc \- Go Packages, accessed February 10, 2026, [https://pkg.go.dev/github.com/ethereum/go-ethereum/rpc](https://pkg.go.dev/github.com/ethereum/go-ethereum/rpc)  
16. README.md \- whitebit-exchange/wbt \- GitHub, accessed February 10, 2026, [https://github.com/whitebit-exchange/wbt/blob/main/README.md](https://github.com/whitebit-exchange/wbt/blob/main/README.md)  
17. ethereum package \- github.com/m-quigley/op-geth \- Go Packages, accessed February 10, 2026, [https://pkg.go.dev/github.com/m-quigley/op-geth](https://pkg.go.dev/github.com/m-quigley/op-geth)  
18. How can I expose Geth's RPC server to external connections? \- Ethereum Stack Exchange, accessed February 10, 2026, [https://ethereum.stackexchange.com/questions/3163/how-can-i-expose-geths-rpc-server-to-external-connections](https://ethereum.stackexchange.com/questions/3163/how-can-i-expose-geths-rpc-server-to-external-connections)  
19. Configure ports \- Besu documentation, accessed February 10, 2026, [https://besu.hyperledger.org/public-networks/how-to/connect/configure-ports](https://besu.hyperledger.org/public-networks/how-to/connect/configure-ports)  
20. Connecting to Ethereum node in web browser \- Stack Overflow, accessed February 10, 2026, [https://stackoverflow.com/questions/32111063/connecting-to-ethereum-node-in-web-browser](https://stackoverflow.com/questions/32111063/connecting-to-ethereum-node-in-web-browser)  
21. Tendermint RPC, accessed February 10, 2026, [https://docs.tendermint.com/master/rpc/](https://docs.tendermint.com/master/rpc/)  
22. Config.toml \- main \- CometBFT Documentation, accessed February 10, 2026, [https://docs.cometbft.com/main/references/config/config.toml](https://docs.cometbft.com/main/references/config/config.toml)  
23. What is a Solana RPC Node? \- GetBlock.io, accessed February 10, 2026, [https://getblock.io/blog/what-is-solana-rpc-node/](https://getblock.io/blog/what-is-solana-rpc-node/)  
24. Setup a Solana RPC Node, accessed February 10, 2026, [https://docs.solanalabs.com/operations/setup-an-rpc-node](https://docs.solanalabs.com/operations/setup-an-rpc-node)  
25. Besu Configuration File \- Hyperledger Bevel, accessed February 10, 2026, [https://hyperledger-bevel.readthedocs.io/en/latest/guides/networkyaml-besu/](https://hyperledger-bevel.readthedocs.io/en/latest/guides/networkyaml-besu/)  
26. Besu API | Besu documentation, accessed February 10, 2026, [https://besu.hyperledger.org/public-networks/reference/api](https://besu.hyperledger.org/public-networks/reference/api)  
27. eth\_blockNumber \- Ethereum \- GetBlock Docs, accessed February 10, 2026, [https://docs.getblock.io/api-reference/ethereum-eth/eth\_blocknumber-ethereum](https://docs.getblock.io/api-reference/ethereum-eth/eth_blocknumber-ethereum)  
28. Time Tells All: Deanonymization of Blockchain RPC Users with Zero Transaction Fee (Extended Version) \- arXiv, accessed February 10, 2026, [https://arxiv.org/html/2508.21440](https://arxiv.org/html/2508.21440)  
29. Blockchain Penetration Testing: Definition, Process, and Tools \- Cyphere, accessed February 10, 2026, [https://thecyphere.com/blog/blockchain-penetration-testing/](https://thecyphere.com/blog/blockchain-penetration-testing/)  
30. Geth Source Code Series: Geth Overall Architecture \- ChainCatcher, accessed February 10, 2026, [https://www.chaincatcher.com/en/article/2201628](https://www.chaincatcher.com/en/article/2201628)  
31. RPC Methods (Detailed Breakdown) \- VeChain Docs, accessed February 10, 2026, [https://docs.vechain.org/developer-resources/evm-compatibility-for-developers/rpc-methods-detailed-breakdown](https://docs.vechain.org/developer-resources/evm-compatibility-for-developers/rpc-methods-detailed-breakdown)  
32. Ethereum Node Types Explained (And Why They Can Make or Break Your Debugging) | by Andrey Obruchkov | Medium, accessed February 10, 2026, [https://medium.com/@andrey\_obruchkov/ethereum-node-types-explained-and-why-they-can-make-or-break-your-debugging-fc8d89b724cc](https://medium.com/@andrey_obruchkov/ethereum-node-types-explained-and-why-they-can-make-or-break-your-debugging-fc8d89b724cc)  
33. Tendermint RPC, accessed February 10, 2026, [https://docs.tendermint.com/v0.33/rpc/](https://docs.tendermint.com/v0.33/rpc/)  
34. EtherHiding: Fake CAPTCHAs, Click-Fix Lures, and Blockchain-Backed Payload Delivery, accessed February 10, 2026, [https://censys.com/blog/etherhiding-fake-captchas-click-fix-lures-blockchain-backed-payload-delivery](https://censys.com/blog/etherhiding-fake-captchas-click-fix-lures-blockchain-backed-payload-delivery)  
35. Authenticate over JSON-RPC requests | Besu documentation, accessed February 10, 2026, [https://besu.hyperledger.org/public-networks/how-to/use-besu-api/authenticate](https://besu.hyperledger.org/public-networks/how-to/use-besu-api/authenticate)  
36. Geth API — web3.py 7.13.0 documentation, accessed February 10, 2026, [https://web3py.readthedocs.io/en/latest/web3.geth.html](https://web3py.readthedocs.io/en/latest/web3.geth.html)  
37. Geth API — web3.py 7.14.0 documentation, accessed February 10, 2026, [https://web3py.readthedocs.io/en/stable/web3.geth.html](https://web3py.readthedocs.io/en/stable/web3.geth.html)  
38. Besu documentation: Welcome, accessed February 10, 2026, [https://besu.hyperledger.org/](https://besu.hyperledger.org/)  
39. Configuration \- Tendermint Core, accessed February 10, 2026, [https://docs.tendermint.com/v0.34/tendermint-core/configuration.html](https://docs.tendermint.com/v0.34/tendermint-core/configuration.html)  
40. Configuration | Tendermint Core, accessed February 10, 2026, [https://docs.tendermint.com/v0.33/tendermint-core/configuration.html](https://docs.tendermint.com/v0.33/tendermint-core/configuration.html)  
41. Public Ethereum RPC Endpoints: Complete guide \- NOWNodes, accessed February 10, 2026, [https://nownodes.io/blog/public-ethereum-rpc-endpoints-complete-guide/](https://nownodes.io/blog/public-ethereum-rpc-endpoints-complete-guide/)  
42. What Is Double Signing? | Coinbase, accessed February 10, 2026, [https://www.coinbase.com/developer-platform/discover/insights/double-signing](https://www.coinbase.com/developer-platform/discover/insights/double-signing)  
43. Blockchain Attacks & Defense \- Cidint, accessed February 10, 2026, [https://www.cidint.in/blockchain-attacks-and-defense](https://www.cidint.in/blockchain-attacks-and-defense)  
44. A Security Engineer's Guide to Reviewing Core Blockchain Nodes \- Sigma Prime, accessed February 10, 2026, [https://blog.sigmaprime.io/core-node-security.html](https://blog.sigmaprime.io/core-node-security.html)  
45. Cubist Blog \- Slashing risks you need to think about when restaking, accessed February 10, 2026, [https://cubist.dev/blog/slashing-risks-you-need-to-think-about-when-restaking](https://cubist.dev/blog/slashing-risks-you-need-to-think-about-when-restaking)  
46. A Primer on Slashing \- Coinbase Institutional Education, accessed February 10, 2026, [https://www.coinbase.com/institutional/research-insights/resources/education/slashing-primer](https://www.coinbase.com/institutional/research-insights/resources/education/slashing-primer)  
47. Software Supply Chain Security of Web3 \- arXiv, accessed February 10, 2026, [https://arxiv.org/html/2511.12274v1](https://arxiv.org/html/2511.12274v1)  
48. Validator vs RPC Node: What's the Difference? | by Alex Carter | Medium, accessed February 10, 2026, [https://medium.com/@alexcarter98zr/validator-vs-rpc-node-whats-the-difference-14c19e6cdc74](https://medium.com/@alexcarter98zr/validator-vs-rpc-node-whats-the-difference-14c19e6cdc74)  
49. Security Overview · tendermint/tendermint \- GitHub, accessed February 10, 2026, [https://github.com/tendermint/tendermint/security](https://github.com/tendermint/tendermint/security)  
50. Tendermint RPC \- Humans.ai Docs, accessed February 10, 2026, [https://docs.humans.ai/developer/api/tendermint-rpc](https://docs.humans.ai/developer/api/tendermint-rpc)  
51. Tendermint: What It Is and How It Works \- dYdX, accessed February 10, 2026, [https://www.dydx.xyz/crypto-learning/tendermint](https://www.dydx.xyz/crypto-learning/tendermint)  
52. Why Separating Control and Data Planes Matters in Application Security | Imperva, accessed February 10, 2026, [https://www.imperva.com/blog/why-separating-control-and-data-planes-matters-in-application-security/](https://www.imperva.com/blog/why-separating-control-and-data-planes-matters-in-application-security/)  
53. Understanding Gateway API Split Architecture: Control Plane vs. Data Plane, accessed February 10, 2026, [https://blog.nginx.org/blog/understanding-gateway-api-split-architecture-control-plane-vs-data-plane](https://blog.nginx.org/blog/understanding-gateway-api-split-architecture-control-plane-vs-data-plane)  
54. Control Plane vs Data Plane: Key Differences Explained \- Pinggy, accessed February 10, 2026, [https://pinggy.io/blog/control\_plane\_vs\_data\_plane/](https://pinggy.io/blog/control_plane_vs_data_plane/)  
55. Separating Agreement from Execution to Improve the Scalability of Blockchains Information Systems and Computer Engineering \- sistema Fenix, accessed February 10, 2026, [https://fenix.tecnico.ulisboa.pt/downloadFile/1407770020547363/86410-Diogo-Fernandes-dissertacao.pdf](https://fenix.tecnico.ulisboa.pt/downloadFile/1407770020547363/86410-Diogo-Fernandes-dissertacao.pdf)  
56. How Blockchain Networks Performed During October 2025's Market Crash and AWS Outage, accessed February 10, 2026, [https://medium.com/@Grace\_Nelo/infrastructure-stress-test-5329d45c131f](https://medium.com/@Grace_Nelo/infrastructure-stress-test-5329d45c131f)  
57. RPC Infrastructure Management Guide for dApps \- dRPC, accessed February 10, 2026, [https://drpc.org/blog/rpc-infrastructure-management-guide/](https://drpc.org/blog/rpc-infrastructure-management-guide/)  
58. Solana Endpoint Security | Quicknode Docs, accessed February 10, 2026, [https://www.quicknode.com/docs/solana/endpoint-security](https://www.quicknode.com/docs/solana/endpoint-security)  
59. Ethereum execution client logging \- SlingNode, accessed February 10, 2026, [https://slingnode.com/2023/01/09/ethereum-execution-client-logging/](https://slingnode.com/2023/01/09/ethereum-execution-client-logging/)  
60. How to make geth log RPC calls? \- Ethereum Stack Exchange, accessed February 10, 2026, [https://ethereum.stackexchange.com/questions/30847/how-to-make-geth-log-rpc-calls](https://ethereum.stackexchange.com/questions/30847/how-to-make-geth-log-rpc-calls)  
61. How to Fix OpenTelemetry Exporter Authentication Failures, accessed February 10, 2026, [https://oneuptime.com/blog/post/2026-02-06-fix-opentelemetry-exporter-authentication-failures/view](https://oneuptime.com/blog/post/2026-02-06-fix-opentelemetry-exporter-authentication-failures/view)  
62. ForensicTransMonitor: A Comprehensive Blockchain Approach to Reinvent Digital Forensics and Evidence Management \- MDPI, accessed February 10, 2026, [https://www.mdpi.com/2078-2489/15/2/109](https://www.mdpi.com/2078-2489/15/2/109)  
63. Authenticated E-Discovery: Utilizing Blockchain for Robust Security and Trust in Digital Evidence \- Ankura.com, accessed February 10, 2026, [https://ankura.com/insights/authenticated-e-discovery-utilizing-blockchain-for-robust-security-and-trust-in-digital-evidence](https://ankura.com/insights/authenticated-e-discovery-utilizing-blockchain-for-robust-security-and-trust-in-digital-evidence)  
64. Blockchain Penetration Testing & Security Audits Guide \[2026\] \- Nadcab Labs, accessed February 10, 2026, [https://www.nadcab.com/blog/blockchain-penetration-testing-security-audits-guide](https://www.nadcab.com/blog/blockchain-penetration-testing-security-audits-guide)  
65. Blockchain Audit Methods and Processes \- Beosin, accessed February 10, 2026, [https://beosin.com/resources/Blockchain\_Audit\_Methods\_and\_Processes.pdf](https://beosin.com/resources/Blockchain_Audit_Methods_and_Processes.pdf)  
66. How To Audit a Smart Contract? \- Chainlink, accessed February 10, 2026, [https://chain.link/education-hub/how-to-audit-smart-contract](https://chain.link/education-hub/how-to-audit-smart-contract)  
67. Error when connecting geth to local network rpc \- Ethereum Stack Exchange, accessed February 10, 2026, [https://ethereum.stackexchange.com/questions/39809/error-when-connecting-geth-to-local-network-rpc](https://ethereum.stackexchange.com/questions/39809/error-when-connecting-geth-to-local-network-rpc)  
68. Ethereum RPC API | Blockchain RPC \- Google Cloud Documentation, accessed February 10, 2026, [https://docs.cloud.google.com/blockchain-rpc/docs/rpc-api](https://docs.cloud.google.com/blockchain-rpc/docs/rpc-api)  
69. Solana Network Outage: What Happened and What's Next \- MOSS, accessed February 10, 2026, [https://moss.sh/news/solana-network-outage-what-happened-and-whats-next/](https://moss.sh/news/solana-network-outage-what-happened-and-whats-next/)  
70. Implementing Continuous Drift Detection in CI/CD Pipelines with GitHub Actions Workflow, accessed February 10, 2026, [https://www.firefly.ai/academy/implementing-continuous-drift-detection-in-ci-cd-pipelines-with-github-actions-workflow](https://www.firefly.ai/academy/implementing-continuous-drift-detection-in-ci-cd-pipelines-with-github-actions-workflow)  
71. AI SRE in Practice: Diagnosing Configuration Drift in Deployment Failures \- Komodor, accessed February 10, 2026, [https://komodor.com/blog/ai-sre-in-practice-diagnosing-configuration-drift-in-deployment-failures/](https://komodor.com/blog/ai-sre-in-practice-diagnosing-configuration-drift-in-deployment-failures/)  
72. Inside Blockchain Startups: Precision Strategies to Sidestep Technical Pitfalls, accessed February 10, 2026, [https://emergingsociety.org/index.php/efltajet/article/download/247/246](https://emergingsociety.org/index.php/efltajet/article/download/247/246)  
73. Bringing Slashing to Solana \- Helius, accessed February 10, 2026, [https://www.helius.dev/blog/bringing-slashing-to-solana](https://www.helius.dev/blog/bringing-slashing-to-solana)  
74. Risk Management for Staking: Slashing \- Figment, accessed February 10, 2026, [https://www.figment.io/insights/risk-management-for-staking-slashing/](https://www.figment.io/insights/risk-management-for-staking-slashing/)