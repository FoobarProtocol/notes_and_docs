## Gnosis Double Hash Vulnerability

>   *All versions of the Gnosis Safe logic contract are affected* (0.0.1-1.4.1)
>
>   Here’s my Ethereum address for the purpose of any and all bug bounty rewards [in accordance with the smart account bug bounty details published here](https://docs.safe.global/advanced/smart-account-bug-bounty): 0x04A37520cBf3B80C843e9dbacE4f163e91b50A41

The goal of this document is to serve as a forensic analysis of the Gnosis Safe vulnerability exploited in the Bybit exchange hack on February 21st, 2025. The core issue highlighted is a critical flaw in the handling of transaction signature validation within the Gnosis Safe smart contract (all versions `1.1.1-1.4.1` are affected), specifically involving improper mixing and nesting of Ethereum signature standards (`EIP-712` and `EIP-191`). The attackers leveraged this vulnerability to execute unauthorized transactions via a sophisticated hash collision mechanism.

The document meticulously reconstructs the attack through a detailed examination of the Ethereum Virtual Machine (EVM) execution trace, carefully stepping through each opcode instruction and analyzing the calldata structure, memory operations, and cryptographic hash computations that occur during execution. By using debugging tools (such as the `cast` command from the Foundry suite), the author replicates the transaction’s environment to precisely identify and visualize the EVM state transitions.

A central finding is the unintended mutation of the transaction hash (`txHash`) during the signature verification process. Initially computed correctly using the `EIP-712` standard, the hash is later erroneously encapsulated within an additional `EIP-191` Ethereum Signed Message structure. This nesting results from a conditional statement in the checkSignatures function of the Gnosis Safe smart contract, triggered when the signature’s parity byte (v value) exceeds 30. This improper re-hashing effectively transforms the original transaction hash, allowing attackers who pre-computed signatures for the maliciously mutated hash to pass signature verification.

The analysis rigorously demonstrates how this hash mutation occurs at the EVM opcode level. Specifically, it shows how the EVM uses `abi.encodePacked` combined with an `EIP-191` personal message prefix ("`\x19Ethereum Signed Message:\n32`") alongside the already calculated EIP-712 structured hash, thus deviating from the intended signature validation protocol. This dual encoding approach significantly narrows the entropy of possible inputs, substantially increasing the feasibility of generating a hash collision. Consequently, attackers were able to forge valid-looking signatures from the perspective of the compromised validation logic.

In conclusion, the document presents unequivocal proof of how the attackers exploited the subtle yet catastrophic misimplementation of signature verification standards in Gnosis Safe’s logic contract. It underscores the critical importance of strict adherence to cryptographic standards and demonstrates how seemingly minor deviations can dramatically weaken security guarantees, allowing sophisticated adversaries to compromise high-value targets like the Bybit exchange.

### Working Our Way from the Start

Okay, let's tackle this step-by-step, starting with breaking down the provided calldata into 32-byte words.

Below is the calldata, broken into 32-byte (64 hex character) chunks, as the EVM would process it:

```plaintext
1: 6a76120200000000000000000000000096221423681a6d52e184d440a8efcebb105c7242  // Function selector + 'to' address
2: 0000000000000000000000000000000000000000000000000000000000000000          // 'value' (0)
3: 0000000000000000000000000000000000000000000000000000000000000140          // Offset to 'data' (320 in decimal)
4: 0000000000000000000000000000000000000000000000000000000000000001          // 'operation' (1 = DELEGATECALL)
5: 000000000000000000000000000000000000000000000000000000000000b2b2          // 'safeTxGas'
6: 0000000000000000000000000000000000000000000000000000000000000000          // 'baseGas'
7: 0000000000000000000000000000000000000000000000000000000000000000          // 'gasPrice'
8: 0000000000000000000000000000000000000000000000000000000000000000          // 'gasToken'
9: 0000000000000000000000000000000000000000000000000000000000000000          // 'refundReceiver'
10: 00000000000000000000000000000000000000000000000000000000000001c0          // Offset to 'signatures' (448 in decimal)
11: 0000000000000000000000000000000000000000000000000000000000000044          // Length of 'data' (68 in decimal)
12: a9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be2969516  // 'transfer' function selector + address
13: 0000000000000000000000000000000000000000000000000000000000000000          // Amount for 'transfer' (0 - not relevant for DELEGATECALL exploit)
14: 00000000000000000000000000000000000000000000000000000000000000c3          // Length of 'signatures' (195 in decimal)
15: d0afef78a52fd504479dc2af3dc401334762cbd05609c7ac18db9ec5abf4a07a          // Start of 'signatures' data
16: 5cc09fc86efd3489707b89b0c729faed616459189cb50084f208d03b201b001f
17: 1f0f62ad358d6b319d3c1221d44456080068fe02ae5b1a39b4afb1e6721ca7f9
18: 903ac523a801533f265231cd35fc2dfddc3bd9a9563b51315cf9d5ff23dc6d2c
19: 221fdf9e4b878877a8dbeee951a4a31ddbf1d3b71e127d5eda44b4730030114b
20: aba52e06dd23da37cd2a07a6e84f9950db867374a0f77558f42adf4409bfd569
21: 673c1f0000000000000000000000000000000000000000000000000000000000
```

#### Calldata Element Mapping and Expected Behavior

Let's map these words to the `execTransaction` parameters and describe what we'd *expect* to happen in a normal execution:

```solidity
function execTransaction(
    address to,
    uint256 value,
    bytes calldata data,
    uint8 operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address refundReceiver,
    bytes calldata signatures
)
```

-   **Word 1:**
    -   `6a761202`: Function selector for `execTransaction`.
    -   `96221423681A6d52E184D440a8eFCEbB105C7242`: The `to` address (the contract being called, in this case, the malicious contract).
-   **Word 2:**
    -   `0000...0000`: The `value` (amount of ETH being sent). It's 0 in this case.
-   **Word 3:**
    -   `0000...0140`: The *offset* to the `data` parameter. This is `0x140` (320 in decimal), meaning the `data` content starts at byte 320 (relative to the start of the arguments).
-   **Word 4:**
    -   `0000...0001`: The `operation` type. `1` represents `DELEGATECALL`.
-   **Words 5-9:** `safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`. These are all standard parameters for gas handling and refunds.
-   **Word 10:**
    -   `0000...01c0`: The *offset* to the `signatures` parameter. This is `0x1c0` (448 in decimal), meaning the `signatures` content starts at byte 448.
-   **Word 11 (Beginning of `data` content):**
    -   `0000...0044`: The *length* of the `data` parameter. This is `0x44` (68 in decimal), meaning the `data` content is 68 bytes long. **This is crucial for the bug.**
-   **Words 12-13 (The `data` content):**
    -   `a9059cbb...`: This is the calldata for the nested `transfer` function call that the attacker wants to execute via `DELEGATECALL`.
        -   `a9059cbb`: The 4-byte function selector for `transfer(address,uint256)`.
        -   `bdd077f651ebe7f7b3ce16fe5f2b025be2969516`: The address to which the (fake) transfer is being made (the attacker's implementation contract).
        -   `0000...0000`: The amount to transfer.
-   **Word 14 (Beginning of `signatures` content):**
    -     `0000...00c3`: The *length* of the `signatures` parameter.  This is `0xc3` (195 in decimal) indicating that 195 bytes should be read and treated as signatures.
-   **Word 15 Onward (Signature data)**
    -    `d0afef...`: This contains the concatenated ECDSA signatures (r, s, v values).

#### Expected EVM Execution (Without the Bug)

1.  **Function Call:** The EVM identifies `execTransaction` by its selector.
2.  **Argument Loading:** It reads the fixed-size arguments (`to`, `value`, `operation`, etc.) directly.
3.  **Dynamic Data Offsets:** It reads the offsets for `data` (word 3) and `signatures` (word 10).
4.  **`data` Processing:** It uses the `data` offset (320) and length (68) to locate and read the `data` content (words 11-13), which contains the nested `transfer` calldata.
5.  **`signatures` Processing:** It uses the `signatures` offset (448) and length (195) to locate and read the `signatures` content (words 14 onward).
6.  **`checkSignatures`:** The `checkSignatures` function would then:
    -   Iterate through the `signatures` data.
    -   Split each signature into its `r`, `s`, and `v` components.
    -   Use `ECRECOVER` to recover the signer addresses.
    -   Verify that the recovered addresses are valid owners and that enough signatures (meeting the threshold) are provided.
7.  **`DELEGATECALL`:** If signature validation is successful, the `execTransaction` function would execute the `DELEGATECALL` to the `to` address (`0x9622...`) with the `data` content (the malicious `transfer` call).

### Breaking Down `execTransaction`

Below is the data typically contained in the `head` of that function: 

| Offset (bytes) | Parameter      | Type          |
| -------------: | :------------- | :------------ |
|           0-31 | to             | address       |
|          32-63 | value          | uint256       |
|          64-95 | data offset    | uint256       |
|         96-127 | operation      | uint8 (pad32) |
|        128-159 | safeTxGas      | uint256       |
|        160-191 | baseGas        | uint256       |
|        192-223 | gasPrice       | uint256       |
|        224-255 | gasToken       | address       |
|        256-287 | refundReceiver | address       |
|        288-319 | _nonce         | uint256       |

Now here’s the `tail` data for that specific function: 

| Offset (bytes) | Parameter   | Type    |    Length (bytes) |
| -------------: | :---------- | :------ | ----------------: |
|        320-351 | data length | uint256 |                32 |
|        352-447 | data        | bytes   | 68 (padded to 96) |

Now, we’ve seen what values **should be in this table** (based on online transaction visual analysis tools and services like Etherscan and others). However, these visual breakdowns **do not account for the potentially volatile internal states of the EVM while the specific transaction is being processed**. 

### Stepping Through the Hash Mutation

Our only step remaining at this point is to debug the transaction through a suitable EVM machination capable of replicating the transaction’s execution in a step-by-step manner within a context where parameters like the blockchain state (i.e., block height, ‘world state’, contract storage/execution state/existence), are all identical to what they were at the time the Bybit proxy was compromised initially. 

To get things kicked off, we’re going to opt for the `cast` command (one of the foundational tools in the Foundry toolset for those that have downloaded it locally on their machines). The command (anyone would need) to run to initiate the debugger (in our terminal) for this specific scenario is as follows: `cast run --rpc-url https://mainnet.gateway.tenderly.co/{RPC_KEY} --evm-version berlin -dt -e ${ETHERSCAN_RPC_KEY} -vvv --json --quick 0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882` (you’ll obviously have to substitute in applicable values for your `RPC` URL and Etherscan RPC Key; *both can be obtained for free; the former is offered by countless providers in the space - if you’re wondering who, don’t forget that you’re still a powerful Googler, too*). *Also, please note that the fork you’re running can’t be any earlier than* `Berlin` *since there is a transaction with an* `access list` *that was submitted at the same block height as our hack transaction. So the blockchain cannot debug our transaction at the appropriate block height and state without properly processing that one as well*.

Running the command above (*after pulling the source code for the Bybit proxy and Gnosis Safe contracts down and compiling said contracts*), should lead to some output being printed in the terminal that’s possibly accompanied with a progress bar at the bottom to show the status of the loaded blockchain state before the terminal switches to an `ncurses` looking screen (*or something similar to it; make sure to re-size your terminal window to make it large-ish so all the data from the debugger can be presented and formatted properly by the* `cast` *tool*). 

![newcompressedscreen](https://github.com/user-attachments/assets/77f215fe-75cc-4ae5-814a-815e44c19890)

>   *As one can see above, its really easy to get the debugger up and running + executing on the actual* 

Getting straight to the point here, take a close look at the GIF presented below. It's going to show us what the memory looks like after the `CALLDATALOAD` opcode has been executed in the EVM.  

![newcompressedscreen2](https://github.com/user-attachments/assets/5aae5448-1f9e-4897-a75c-b51810acd870)

This is perhaps the most opaque (or, as many conventionally put it - “hard”) part of the analysis given the abstract and super technical nature of the EVM's execution state and how that relates to the processing of `calldata` within the scope of the general parameters of the Ethereum protocol. 

#### Warming Up to EVM Analysis

Right now, we’re examining the transaction’s execution against the logic of the [Gnosis Safe 1.1.1 implementation address](https://etherscan.io/address/0x34cfac646f301356faa8b21e94227e3583fe3f5f). 

When stepping through an EVM debugger like this, there will usually be at least 4 fields shown on the screen/interface of whatever tool you're using: (1) Source code [hopefully] of the verified contracts as various functions and actions are being performed by them (2) Opcodes (known as ‘mnemonic’ within the scope of these activities), that each dictate nominal behaviors within the EVM state that can read and/or write to and from the `memory` and the `stack`. (3) The last two elements are the `memory` and the `stack`. 

**Quick Example** 

Check out the screenshot below (*this is from the same hacked transaction that we’ve been discussing*): 

![image](https://github.com/user-attachments/assets/9bcd3bc4-7435-4535-b955-900e61b03a81)

1.   At this point, the `delegatecall` from the Bybit proxy that forwarded this call to the logic contract has already been executed. 
2.   If we look at the panel at the very top of the screenshot above, we can see that our counter is currently stopped right before an opcode named `PUSH 1` with a corresponding value of `0x40`. 

![image](https://github.com/user-attachments/assets/357a3369-abe4-4874-85b0-e1a2b8787d97)


When we move forward to the next step in the debug session, we'll notice that our stack has an additional item on top - `0x40`. Below is an updated image showing the changed stack with this item appended on top. 

![image](https://github.com/user-attachments/assets/9c3dcffd-d61a-4b91-b1b2-c4c2c016a39a)

As the ‘stack label’ helpfully shows, this `0x40` value actually points to an ‘’offset’ in the memory. An ‘offset’ simply tells the EVM where to look for certain data. To help illustrate this, I drew an arrow from the top item on the stack (that was just pushed on there) to the `0x40` offset in the memory. 

>   It's important to remember we’re working with* **hexadecimal values here**. *So an offset of* `0x40` *converts to the number* **64** *in decimal. What this means is that the location of the data the EVM is being to starts at the 65th byte. Remembering our lesson about 32-byte words being the status quo for the EVM, we can quickly confirm that the* ``0x40` *offset is the 3rd memory slot* (the first two slots = 32-bytes a piece, so the end of the 2nd slot = 64 bytes and thus, our data offset takes us to the third slot in the memory). 

![image](https://github.com/user-attachments/assets/520e3228-83a0-4c26-a9f6-d4d7823c2996)

Now that we all have at least somewhat of a grasp on how the EVM works, let's go see if we can't find something interesting.

#### Where Things Start to Get Interesting

As we continue to step through the execution flow of the hack transaction, it isn't too long before we can see **firsthand** the impact of data corruption in the EVM via the Head Overflow Re-encoding Tuple bug. Before delving into how, let‘s orient ourselves first. 

Right now, we're at PC # 16334 (otherwise known as the ‘counter’). Right now, the logic contract is in the middle of stepping through the routine for the function `encodeTransactionData`. I have that re-posted below (in its entirety) for convenience sake: 

````solidity
function encodeTransactionData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes memory) {
        bytes32 safeTxHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                _nonce
            )
        );
        return
            abi.encodePacked(
                bytes1(0x19),
                bytes1(0x01),
                domainSeparator,
                safeTxHash
            );
    }
````

>   *Specifically, we're at line 13-27 in the code of the function you see above.*

Let’s start by taking a look at how the EVM rotates, loads and then saves the respective values for each argument in the `encodeTransactionData` struct. 

![output_compressed](https://github.com/user-attachments/assets/10b7b45d-16c3-4d4f-850e-2c0bba063452)

-   First, we see the opcode `PUSH32` attached to the value `0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8`. Notably at the bottom panel, we can see the first parameter of the `encodeTransactionData` struct (`SAFE_TX_TYPEHASH`) is highlighted as well. Those following along will note that this 32-byte value is equivalent to the declared `const SAFE_TX_TYPEHASH`. In the next frame, we can see that very same hexadecimal value being pushed to the top of the stack. 

-   After that value is moved to the top of the stack, the next instruction dictates that `0x00` (null bytes) be pushed to the top of the stack via `PUSH1` (`0x00`). 

-   Following that operation, a `SHL` (shift left) opcode appears, which effectively swaps the top two items on the stack (moving the `SAFE_TX_TYPEHASH` value back to the top of the stack). 

-   Finally (at the conclusion of our GIF), there is a `DUP13` opcode executed on the stack at the same time we see the `to` parameter being highlighted by the debugger too. Let's examine why that is. 

![image](https://github.com/user-attachments/assets/300a6330-69e1-4990-8349-ca15325fa877)

Keen observers likely noticed that our GIFs and screenshots do not show the entire depth of the stack and that’s because we (or I, at least), do not have enough real estate on my screen to dig back that deep. But not to fear - we can still scroll down the stack to examine the other values that exist ‘below the surface’. 

To be clear, the `DUP13` opcode tells the EVM to identify whatever the 13th item is down the stack (from the top; remember the first starts at `0x00`), then **duplicate the value of that item** and push the result to the top.

![image](https://github.com/user-attachments/assets/2a321c44-935b-4982-9d67-7ee59934a28f)

>   *As we can see above, the item at the 13th position on the stack* (it says ‘12’ because the first slot starts at ‘0’), *the 32-byte value present is* `00000000000000000000000096221423681a6d52e184d440a8efcebb105c7242`

We can tell the `00000000000000000000000096221423681a6d52e184d440a8efcebb105c7242` value is an address because its left-padded with 24 zeroes (12-bytes), followed by 20-bytes, which is standard for how addresses in Ethereum are padded (addresses are left-padded specifically because they're encoded in `little endian`, not `big endian`; so the least significant byte is on the far left). 

Removing the zeroes, we’re left with `0x96221423681a6d52e184d440a8efcebb105c7242`. And if we double back to check the decoded `calldata` for this transaction, we can confirm this indeed matches what should be expected from the `to` of that specific function (since all of the parameters for the `encodeTransactionData` function are derived from the inputs that were used to craft the `execTransaction` function call that was made on the front-facing proxy). 

For reference (and convenience sake), we have an abbreviated `json` structure of the hack transaction: 

````json
{
  “to”: “0x96221423681a6d52e184d440a8efcebb105c7242”,
  “value”: “0”,
  “data”: “0xa9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be29695160000000000000000000000000000000000000000000000000000000000000000”,
  “operation”: 1,
  “safeTxGas”: “45746”,
  “baseGas”: “0”,
  “gasPrice”: “0”,
  “gasToken”: “0x0000000000000000000000000000000000000000”,
  “refundReceiver”: “0x0000000000000000000000000000000000000000”,
  “signatures”: “0xd0afef78a52fd504479dc2af3dc401334762cbd05609c7ac18db9ec5abf4a07a5cc09fc86efd3489707b89b0c729faed616459189cb50084f208d03b201b001f1f0f62ad358d6b319d3c1221d44456080068fe02ae5b1a39b4afb1e6721ca7f9903ac523a801533f265231cd35fc2dfddc3bd9a9563b51315cf9d5ff23dc6d2c221fdf9e4b878877a8dbeee951a4a31ddbf1d3b71e127d5eda44b4730030114baba52e06dd23da37cd2a07a6e84f9950db867374a0f77558f42adf4409bfd569673c1f”
}
````

The next member of the struct is the `value` parameter, which we know is `0`. And we see that pushed to the top of the stack above our `to` address value. 

![image](https://github.com/user-attachments/assets/cf25b9a6-acff-4f3b-90fc-abe121c7b903)

Finally, we find ourselves at the `keccak(data)` portion of the struct. But first, this element must be loaded from the `calldata`. Since this is a dynamic type, the EVM must be instructed on where to find said data. That’s the purpose of the `offset` value being pushed to the top of the stack first. 

![image](https://github.com/user-attachments/assets/ed6f79fe-3891-4cdc-a16e-4ecf8d55324c)

![image](https://github.com/user-attachments/assets/9ca8a912-5352-4073-b40e-9edd43898d2f)

As we can see, the offset value that gets pushed to the top of the stack is `0x80`. In this instance, we’re being provided an `offset` (in the EVM) to find the `length` byte for the dynamic `data` variable (*extracted from the* `calldata`). The hexadecimal `0x80` is equivalent to `128` in decimal form. 

This means that the start of the `data` element is 128 bytes from the start of the `calldata` (four 32-byte words). Math wizards out there will likely notice that this is an exact multiple of 32 `(4*32 = 128)`. That tells the EVM to pull out the value `0x44` located at that offset.

That hexadecimal (`0x44`) correlates with the decimal value 68. 

![image](https://github.com/user-attachments/assets/b985c184-c9c1-4d51-bfac-a1ea00252d66)

From there, the EVM is set to swap the top two values in our stack with one another, which will result in `0x80` being placed at the top once again. From there, the value `0x20` will be placed at the top of the stack, followed by an `ADD` operation. 

![image](https://github.com/user-attachments/assets/3eaea10e-212d-4298-ad1a-af1ad94fa703)

So that means `0x80` gets added to `0x20`, which gives us `0xa0` in hexadecimal (which is `160` in decimal). That becomes the offset pointing to the value in memory that `keccak256` should be iterating over. 

![image](https://github.com/user-attachments/assets/3d935eaa-9f23-4c31-a22e-223b39147195)

So as we can see above, the value to be hashed will be the full `data` array, which is notably **unpadded** (this is proper EVM convention). The result from that is the value `0x91c06c0d3750c6c35073a3c5e3f4c7d9ce12c14bd0212a8c83f1e24b46bd654e`. 

![image](https://github.com/user-attachments/assets/a8dc61cc-d3c5-4224-bc38-985f9c548a9b)

So that means `0x80` gets added to `0x20`, which gives us `0xa0` in hexadecimal (which is `160` in decimal). That becomes the offset pointing to the value in memory that `keccak256` should be iterating over. 

![image](https://github.com/user-attachments/assets/bd08fb4f-7f27-4795-a2c3-56c28c4e0fbd)

So as we can see above, the value to be hashed will be the full `data` array. The hash function leaves us with a resulting value of `0x91c06c0d3750c6c35073a3c5e3f4c7d9ce12c14bd0212a8c83f1e24b46bd654e`. 

![image](https://github.com/user-attachments/assets/61dbe4b7-a405-49c3-bc8f-22cb8b0d6b58)

From here, we're going to work’ our way to the part where our EVM has highlighted the line: `abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce)`. After the data portion was hashed (using `keccak256`), it was included as a member of the struct ready to be encoded using the `abi.encode`. Right now, we’ve worked our way all the way to the part where our EVM has highlighted the line `abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce)`. After the `data` portion was hashed (using `keccak256`), it was included as a member of the struct ready to be encoded using the `abi.encode` solution. 

![image](https://github.com/user-attachments/assets/b3660c2a-fab5-4cc8-9713-1b7baa80589d)

This line of code entails various opcodes (i.e., `DUP13`, `DUP12`, etc.), in a sequential process that involves placing the struct items at the top of the stack (in order from left to right as you would read it from the highlighted struct), duplicating said value and then performing an `MSTORE` command. The original value for the `offset` of the first element in the `struct` was loaded with an `MLOAD` opcode on the scratch space at `0x40`. From there, the EVM merely adds another `0x20` (32 bytes in decimal) to the prior offset, which moves it to the next memory slot for the value to be written. 

If that’s confusing, hopefully this GIF below clears things up a bit: 

![image](https://github.com/user-attachments/assets/a767a10c-a857-4c35-bb27-15a92f53de36)

This next screenshot shows 11 memory slots that were appended to the buffer (expanding us to 640 bytes total; no problem). 

![image](https://github.com/user-attachments/assets/8fc4f114-2537-400d-8779-94eae04b796e)

Once that process finishes, all of those duplicated items from our stack that were used to write to the memory buffer are ‘popped’ off the stack (via the `POP` opcode). Following that, the EVM loads the value at offset `0x40` (our scratch space), which was `0x100` at that time. 

![image](https://github.com/user-attachments/assets/5ad01c17-512b-4d51-a0d8-8135a5abfcf5)

From there, a bunch of different `DUP` opcodes (reaching back to various shallow depths in our stack [none more than 4 stack items deep]), and arithmetic commands are performed on these values. Once these operations are completed, the EVM’s next opcode to execute in the counter is an `MSTORE` command on the top two items of the stack. 

Those two items are `0x100` (for the offset) and `0x160` (for the value). This means, of course, that the value `0x160` (which is likely an offset in itself), is going to be stored at memory slot `0x100`.  

>   *For quick reference* ,`0x100` *is hexadecimal for the decimal* `256`. If we divide that number by `32`, then the result (`8`), tells us how many slots down we need to travel in our memory to determine whether that value (`0x100`) is going to be placed. *The value* `0x160` *is* `352`. 

![image](https://github.com/user-attachments/assets/0da25d90-7fd7-40c7-b768-079e7f3e4d07)

From that point, the EVM starts setting the stage for signature verification and validation. 

#### Signature Verification and Validation

This process starts with the storage of the value `0x280` at the offset `0x40`. For reference, `0x280` represents the number `640` in decimal. 

![image](https://github.com/user-attachments/assets/7bd206af-e708-4970-ac6f-b49b07654ae7)

![image](https://github.com/user-attachments/assets/a68b529b-a5e3-442b-9d0a-38eee8526e75)

The value that was stored at offset `0x100` in the memory buffer (`0x160`) is the next step in the EVM’s execution. From there, the offset value [`0x160`], (which was at offset `0x100`) and loaded to the top of the stack is swapped back to the second in the stack (via `SWAP 1` opcode), with the offset value where the value `0x160` was at. Once that offset value is swapped back to the top of the stack, an `0x20` (32 bytes), is pushed to the top of the stack and then the two top stack values (`0x100` and `0x20`), are then added together to create a new value, which is then labeled as an `offset`. 

![image](https://github.com/user-attachments/assets/37641744-5629-47d7-8107-387c970ead93)

![image](https://github.com/user-attachments/assets/df6e81d4-8fe4-4f60-aa33-65e71287edc0)

There are a few things that are about to happen, so let’s keep up with them for a second by outlining where we are: 

-   The next opcode in the EVM counter is `KECCAK256`. The top two stack items (highlighted) in that very last picture shows us the values that will be concatenated and used as input for the `KECCAK256` hash function. 

-   The offset (`0x120`), points the EVM to the proper place in the memory to perform the `keccak256` operation. 

-   The `size` dictates how many bytes of data (from that offset point) that the hash function will process. 

-   Taking the prior two bullet points into consideration, the EVM is going to be looking specifically for an offset at `0x120` (288 bytes) and the EVM is to take the following 352 bytes from that offset point and perform the `keccak256` hash function on said data. 

![image](https://github.com/user-attachments/assets/7028a092-8118-4f79-9176-c80e01e4b381)

![image](https://github.com/user-attachments/assets/fd4d7b56-d3a8-4bd7-9259-1931cc636705)

The result of the `keccak256` operation on this data is `0xea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0` (important to note for reference).This is reflected by the fact that this is the value that was pushed to the top of the stack after the `keccak256` instruction completed.  

This value is **supposed to be** the `safeTxHash` (*this value is* **supposed to be** *critical for signature validation*). 

Once the value for the `safeTxHash` variable has been obtained, our execution process begins down the long, winding road of **signature validation**. The first step to doing so is to start constructing the “**Ethereum Signed Message**” (*as specified per* `EIP-712`). 

*Below is a* **brief** *explainer on how the construction for the message prefixes work and how*: 

![image](https://github.com/user-attachments/assets/f6150525-57b1-40dd-861f-5df2f295b378)
>   **source**: https://eips.ethereum.org/EIPS/eip-712

The reason why we’re spending so much time going over the this portion of the execution trace where it iterates over the statement `return abi.encodePacked(byte(0x19), byte(0x01), domainSeparator, safeTxHash);` (*specifically the* `abi.encodePacked` *encoding that is to be performed on the string with structs packed into it*). 

This starts with the `0x19` byte being placed in the EVM memory via an `MSTORE` opcode which takes `2a0` as its argument (telling us the `offset` the `x19` byte of the `EIP-712` transaction will be stored at).  

![image](https://github.com/user-attachments/assets/3a0ede18-a20c-4394-a59b-905ae8671812)

Shortly thereafter, we see the value `0x01` appended to the `0x19` (null-byte) string prefix. 

**Slight Detour to Explain EIP-712 Signed Messages**

>   *Per the official specification*, “This EIP aims to improve the usability of off-chain message signing for use on-chain. We are seeing growing adoption of off-chain message signing as it saves gas and reduces the number of transactions on the blockchain. Currently signed messages are an opaque hex string displayed to the user with little context about the items that make up the message. ”

`EIP-712` is an Ethereum Improvement Proposal for the `eth_signTypedData` RPC call. TO simplify, an RPC call is what is done whenever one visits a web3-enabled site and either visiting the site or interacting with an element on said site triggers the Metamask modal to pop-up in one’s browser. 

Before the introduction of `EIP-712` signed data, signature requests would typically look like the following: 

![image](https://github.com/user-attachments/assets/52e24c8a-e46a-4089-a9e6-14ca1d88ded3)

After the inception of `EIP-712`, requests adhering to this standard typically appear as thus: 

![image](https://github.com/user-attachments/assets/f52f0a7d-a6d3-48a0-97ca-e35a60a5426b)

>   *Figured this section would be worth the food for thought since there’s been so much commentary regarding the purported* `blind signing` *aspect of the hack*. 

#### Back to Our EVM Analysis

Shortly after storing the `0x19` and `0x01` bytes at the aforementioned memory offset, the EVM then appends the **domain separator** (`0xb3e2d2b1f57b1a87f63b651fa32e792bd57a3bd6476f4c2ea8637a5b6922a1`) and the `safeTxHash` (`0xea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0`). 

When we concatenate these values, we end up with the resulting transaction data: `0x1901b3ded2bdbff5db1a87f6d551fa256e9f2bd6517a3bb84f4c2ea863fb3a559622ea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0`. Following the creation of this concatenated, Ethereum signature, the EVM pushes the value `0x42` (decimal `66`) to slot `0x280`. A bit later we see some interesting activity when the offset at `0x40` gets overwritten. Previously, it had the value of `0x280` (the same value as the slot offset we just wrote our somewhat unusual value of `0x42` to). This new `MSTORE` operation, however, writes the value of `0x2e2` to the `0x40` memory slot. 

Notably, in hexadecimal, the value `0x280` is `640` in decimal (which divides cleanly by `32` to give us `20`. However, this new value of `0x2e2` gives us the decimal equivalent of `738`, which does not divide cleanly (`732/32 = 22.875`). 

![image](https://github.com/user-attachments/assets/4ae8f155-173a-43b3-954b-788255ff950b)

Moving further down, the nonce (stored at key `0x05` is loaded), then incremented by one before being stored back in the same memory spot (permanent storage so this was an `SSTORE` operation). 

Following this, however, we see the `0x42` value get loaded from offset `0x280`. Since this operation pops the top item off the stack, the offset value was first duplicated to allow the EVM to continue working with it. After the `0x42` value was pushed to the top of the stack, the EVM’s instructions swapped that value behind the offset it was retrieved from, then shifted the memory slot 32 bytes down by pushing `0x20` to the top of the stack and then adding it to the `0x280` value (`640` in decimal), to give us the value of `0x2a0` (which is `672` in decimal). Now, the value that was previously stuffed at `0x280` is being used to note the length of the value that needs to be hashed (which is the Ethereum signed message that was crafted prior). 

![image](https://github.com/user-attachments/assets/b67b4819-dd72-4d92-abe4-1465fdbec6f3)

When the `keccak256` hash function is performed on this data, it gives us a value for the `txHash`, which is `0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8`. This value is **important**, so store that somewhere safe in your mind. 

![image](https://github.com/user-attachments/assets/f22f9fcf-2c31-4f88-b0e8-d1acd224fa1f)

From here, several dozen instructions are needed for us to iterate through the `checkSignatures` function to the point where we can extract some meaningful takeaways from it. The `checkSignatures` function is not typically listed among this logic contract’s ABI output, so take note of the signature for this function, which is (`checkSignatuers(txHash, txHashData, signatures, true);`). When the `checkSignatures` function name is highlighted, a value of `0x26f7` is pushed to the top of the stack (via a 2-byte `PUSH2` opcode instruction). 

Afterward, the `txHash` function argument is highlighted, which results in a push of the hashed value we obtained a few instructions ago to the top of the stack (`0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8`) via a `DUP3` instruction. 

The next instruction is yet another `DUP3`, which apparently correlates with the `ffHashData` argument of the `checkSignatures` function. The `DUP3` operation results in the value `0x280` being pushed to the top of the stack **for the txHashData** (since it was stored at that offset). Finally, for the `signatures` argument of the function’s arguments, we see a value of `0x1e4` being pushed to the top of the stack via a `DUP8` instruction. Additionally, the value of `0xc3` is pushed to the top of the stack via another `DUP8` instruction. 

Notably, the value `0xc3` is 195 in decimal (which likely will be used to dictate the length of the 3 signatures, since each is meant to be 65 bytes a piece). And the value `0x1e4` (which is 484 in decimal), will likely be used to tell the EVM where in the offset it should consider to be the ‘start’ of the signatures byte array. 

Afterward, the value of `0xc3` has `0x1f` added to it (which was likely done to ensure that the value would be padded to a multiple of 32 bytes; 195/32 doesn’t divide cleanly, however, if we add 29 `0's` to the `195`, we end up with `224`, which is a clean multiple of 32). However, the value that we obtain when we add `0x1f` and `0xc3` together is `0xe2` and its decimal value is `226` (not `224`), which results in the value of `7.0625`. 

Not ironically, the EVM instructions dictate that the newly derived sum of the `0xc3` and `0x1f` values be divided by `0x20` (32 bytes in decimal), which of course would give us a value of `7` (remember, the EVm doesn’t deal with fractions, so it will always round). After `0x07` is obtained from that arithmetic operation and pushed to the top of the stack, the next EVM instruction dictates this value be multiplied by the next item behind it on the stack (`0x20` again), which gives us a value of `0xe0`, which is `224` (so that was the EVM’s way of obtaining the correct padding for the signatures by rounding the quotient of the previously obtained length after dividing it by 32). 

All of this takes us to one of the very few `CALLDATACOPY` commands in this entire execution trace. The top 3 values on the stack reference the `destOffset`, `offset` and `size` for this operation, respectively. The `destOffset` tells the EVM where it should place the data that is being loaded via the `CALLDATACOPY` function and the `offset` tells us where in the `CALLDATA` the EVM should be loading from and the `size` marker tells the EVM how much of the `CALLDATA` should be copied from that `offset` point.

Those values in hexadecimal are `0x302`, `0x1e4` and `0xc3`. Those values are `770`, `484` and `195`, respectively. 

![image](https://github.com/user-attachments/assets/6fab4006-420e-4008-8e3a-4e8e17f3597f)

The `destOffset` in the memory buffer is shown clearly in the screenshot above. The `calldata` load is a little less intuitive. However, all we have to do is count 484 bytes from the start of the RLP-encoded calldata (minus the `0x` prefix). Remember that we’re dealing with bytes here, so that means **968 hexadecimal characters** (484\*2). 

![image](https://github.com/user-attachments/assets/113f19ad-1f01-44a4-9e3a-15de2c2a4ba1)

Above, the highlighted section represents the first 968 bytes of the actual `calldata` (excluding the `0x` prefix): 

![image](https://github.com/user-attachments/assets/8d6924aa-c54a-4bef-a14c-d3b39bffbfd1)

Above, this other highlighted section represents the length (in bytes) that is to be copied from the calldata (via the `CALLDATACOPY` command). As noted, the `size` is denoted as `c3` 

When the `CALLDATACOPY` instruction is executed in the EVM, this is what gets added to the memory buffer. 

![image](https://github.com/user-attachments/assets/2212bb65-1a88-4e7c-97a5-405c4da3c3fc)

That value, of course, is the `signature` data for the transaction itself.

For convenience, the (concatenated) multi-signature submission for the hack transaction is re-posted below: 

-   `d0afef78a52fd504479dc2af3dc401334762cbd05609c7ac18db9ec5abf4a07a5cc09fc86efd3489707b89b0c729faed616459189cb50084f208d03b201b001f1f0f62ad358d6b319d3c1221d44456080068fe02ae5b1a39b4afb1e6721ca7f9903ac523a801533f265231cd35fc2dfddc3bd9a9563b51315cf9d5ff23dc6d2c221fdf9e4b878877a8dbeee951a4a31ddbf1d3b71e127d5eda44b4730030114baba52e06dd23da37cd2a07a6e84f9950db867374a0f77558f42adf4409bfd569673c1f`

Any readers that do not have access to the same CLI tools that are being used for this analysis don't have to feel left out. Etherscan parses and extracts this same information from the `calldata` that was fed to the (now) compromised Bybit proxy that led to the hack. 

>   *That hack transaction can be* [accessed online here](https://etherscan.io/tx/0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882). 

Upon visiting this page (which is the transaction panel for the hack itself), all you really need to do is scroll down a bit until you see a section labeled `Other Attributes` and `Input Data` (on the lefthand side). That will be accompanied with a box to the right that has a bunch of hexadecimal characters in it. Below that box are four buttons. The second button should have the words `Decode Input Data` on it. 

![image](https://github.com/user-attachments/assets/7ce59dc3-bed5-4b7a-a134-871250454dfd)

Decoding the data yields the signature that everyone examining this transaction online has probably seen at this point: 

![image](https://github.com/user-attachments/assets/4f33e490-2fa7-4d67-8e91-53b6e46807df)

>   *Transcribed, this signature is*: `d0afef78a52fd504479dc2af3dc401334762cbd05609c7ac18db9ec5abf4a07a5cc09fc86efd3489707b89b0c729faed616459189cb50084f208d03b201b001f1f0f62ad358d6b319d3c1221d44456080068fe02ae5b1a39b4afb1e6721ca7f9903ac523a801533f265231cd35fc2dfddc3bd9a9563b51315cf9d5ff23dc6d2c221fdf9e4b878877a8dbeee951a4a31ddbf1d3b71e127d5eda44b4730030114baba52e06dd23da37cd2a07a6e84f9950db867374a0f77558f42adf4409bfd569673c1f` (as we extracted from the EVM trace).

##### Continuing Forward

From here the `0xc3` and `0x302` values both get pushed to the top of the stack and then added together with one another, resulting in the value, `0x3c5` (which is `965` in decimal). This value is used as an offset that directs the EVM to an area in the memory beginning right after the end of the signatures `bytes` value. 

![image](https://github.com/user-attachments/assets/c72ceb75-d6c6-4b6f-94c0-7296d2a44747)

The execution of the next instruction (`MSTORE`) results in the following: 

![image](https://github.com/user-attachments/assets/e3bd993b-b450-432a-a059-7a4ff08cd6a0)

Later on in the EVM trace (after the length of the signatures is confirmed), the value `0x2e2` is moved to the top of the stack (via a `DUP4` instruction) and used as the offset for an `MLOAD` operation. However, remembering correctly, the value `0x2e2` is `738` in decimal. Which takes us just beyond the marking of one of the 32-byte offset memory buffer slot locations. 

This is an `MLOAD` operation, so that means it's going to push the 32-byte string it reads (from that offset at `0x2e2`) to the top of the stack. 

![image](https://github.com/user-attachments/assets/649f85fb-1c9c-44ab-92f0-d5efa9273431)


Those that are unfamiliar with dissecting transactions and EVM opcode execution may be surprised to see `0x00` values get pushed to the top of the stack when iterating over the variables for `currentOwner`, `uint8 v`, `bytes32 r` and `bytes32 s`. 

![image](https://github.com/user-attachments/assets/c88e4108-b799-477a-94eb-8a1ff6acb644)

Here is the value that gets pushed for `uint8 v`: 

![image](https://github.com/user-attachments/assets/92babed9-fc17-4d7d-bcef-bdd2aa6d0d8f)

Here’s the value that gets pushed for `bytes32 r`: 

![image](https://github.com/user-attachments/assets/55d34b7c-af8b-4224-9805-80ae3169f3da)

Also, here is the value that gets pushed for `uint256 i`: 

![image](https://github.com/user-attachments/assets/af9ad092-990b-4877-a87e-54bfd150def8)

##### Breaking Down the Problematic `checkSignatures` Block

At this point, the EVM in the transaction trace, the EVM is iterating directly over the signature recovery and validation portion of the hack transaction’s execution. 

As mentioned prior, those routines are contained within the `checkSignatures` function from the [Gnosis Safe Logic Contract](https://etherscan.io/address/0x34cfac646f301356faa8b21e94227e3583fe3f5f), transcribed below for convenience: 

````solidity
function checkSignatures(
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures,
        bool consumeHash
    ) internal {
        // Load threshold to avoid multiple storage loads
        uint256 _threshold = threshold;
        // Check that a threshold is set
        require(_threshold > 0, "Threshold needs to be defined!");
        // Check that the provided signature data is not too short
        require(
            signatures.length >= _threshold.mul(65),
            "Signatures data too short"
        );
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < _threshold; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            // If v is 0 then it is a contract signature
            if (v == 0) {
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint256(r));

                // Check that signature data pointer (s) is not pointing inside the static part of the signatures bytes
                // This check is not completely accurate, since it is possible that more signatures than the threshold are send.
                // Here we only check that the pointer is not pointing inside the part that is being processed
                require(
                    uint256(s) >= _threshold.mul(65),
                    "Invalid contract signature location: inside static part"
                );

                // Check that signature data pointer (s) is in bounds (points to the length of data -> 32 bytes)
                require(
                    uint256(s).add(32) <= signatures.length,
                    "Invalid contract signature location: length not present"
                );

                // Check if the contract signature is in bounds: start of data is s + 32 and end is start + signature length
                uint256 contractSignatureLen;
                // solium-disable-next-line security/no-inline-assembly
                assembly {
                    contractSignatureLen := mload(add(add(signatures, s), 0x20))
                }
                require(
                    uint256(s).add(32).add(contractSignatureLen) <=
                        signatures.length,
                    "Invalid contract signature location: data not complete"
                );

                // Check signature
                bytes memory contractSignature;
                // solium-disable-next-line security/no-inline-assembly
                assembly {
                    // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                    contractSignature := add(add(signatures, s), 0x20)
                }
                require(
                    ISignatureValidator(currentOwner).isValidSignature(
                        data,
                        contractSignature
                    ) == EIP1271_MAGIC_VALUE,
                    "Invalid contract signature provided"
                );
                // If v is 1 then it is an approved hash
            } else if (v == 1) {
                // When handling approved hashes the address of the approver is encoded into r
                currentOwner = address(uint256(r));
                // Hashes are automatically approved by the sender of the message or when they have been pre-approved via a separate transaction
                require(
                    msg.sender == currentOwner ||
                        approvedHashes[currentOwner][dataHash] != 0,
                    "Hash has not been approved"
                );
                // Hash has been marked for consumption. If this hash was pre-approved free storage
                if (consumeHash && msg.sender != currentOwner) {
                    approvedHashes[currentOwner][dataHash] = 0;
                }
            } else if (v > 30) {
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(
                    keccak256(
                        abi.encodePacked(
                            "\x19Ethereum Signed Message:\n32",
                            dataHash
                        )
                    ),
                    v - 4,
                    r,
                    s
                );
            } else {
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, v, r, s);
            }
            require(
                currentOwner > lastOwner &&
                    owners[currentOwner] != address(0) &&
                    currentOwner != SENTINEL_OWNERS,
                "Invalid owner provided"
            );
            lastOwner = currentOwner;
        }
    }
````

To clarify what we saw above as it pertains to the `v`, `r` and `s` values, please **note that we had not yet split any of the signatures or loaded those values from the memory buffer yet**. 

When that happens, the lines of code that are to be executed are: 

````solidity
function signatureSplit(
    bytes memory signatures,
    uint256 pos
) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
    // The signature format is a compact form of:
    //   {bytes32 r}{bytes32 s}{uint8 v}
    // Compact means, uint8 is not padded to 32 bytes.
    // solium-disable-next-line security/no-inline-assembly
    assembly {
        let signaturePos := mul(0x41, pos)
        r := mload(add(signatures, add(signaturePos, 0x20)))
        s := mload(add(signatures, add(signaturePos, 0x40)))
        // Here we are loading the last 32 bytes, including 31 bytes
        // of 's'. There is no 'mload8' to do this.
        //
        // 'byte' is not working due to the Solidity parser, so let's
        // use the second best option, 'and'.
        v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
    }
}
````

Specifically, when the assembly code is being iterated over, that’s when we’ll see actual `r`, `s` and `v` values being pushed to the stack as a result of the `signatureSplit` operation. The reason why one will initially see values of `0` for these variables is because the EVM was ‘initializing’ those variables (by zeroing them out before writing to them). 

Specifically: 

-   When the Solidity compiler generates bytecode for an internal function call (like `signatureSplit`), it inserts instructions to move arguments around, push jump destinations, or clear temporary variables. 
-   In a step-by-step debugger, you can land in these “pre-call” or “post-call” sequences, and at those precise steps, you might see zeros on the stack - even though the function is about to load or has already loaded in the real values. 
-   Internally, Solidity often zero-initializes return slots or local variables before actually writing them. So, at an intermediate step, you might see `v = 0`, `r = 0`, `s = 0` on the stack or in memory, but the function has not yet performed the assembly loads from the `signatures array`. 

Hence why there were multiple `PUSH1` opcode instructions (paired with the value `0x00`). 

![screencap_04032025_09 17PM](https://github.com/user-attachments/assets/c52e110f-74de-4a2d-aeff-dabd5df3e4a2)

We do start to see valid values for the `signatureSplit` function pop-up with the EVM gets to the aforementioned assembly code that’s responsible for isolating each authorized owner’s signature from the concatenated multi-signature string and then splitting that result into `v`, `r` and `s` values which are then used (with the `messageHash`) to recover a public key from the signature. 

The first line of code worth directing one’s attention to is the assembly code responsible for generating the `r` variable. The statement for that is: `r := mload(add(signatures, add(signaturePos, 0x20z))`. This loads the first 32 bytes from the `offset` at `0x302` (770 bytes in decimal). That value that gets loaded is `0xd0afef78a52fd504479dc2af3dc401334762cbd05609c7ac18db9ec5abf4a07a`. 

![image](https://github.com/user-attachments/assets/9e99d9a9-5159-4a61-827d-189b072b1f50)

The next line of code in the assembly block for the `signatureSplit` function is `s := mload(add(signatures, add(signaturePos, 0x40))`. This statement effectively tells the EVM to pick up the next 32 signature bytes (which is where the `s` value should be located for the split signature). 

![image](https://github.com/user-attachments/assets/7ba34bda-37e8-4ae5-b654-8c43d874d110)

That value is: `0x5cc09fc86efd3489707b89b0c729faed616459189cb50084f208d03b201b001f`. 

And, finally, the ‘parity byte’ (`v`) is extracted (1-byte) after it gets pushed to the top of the stack from the offset `0x323` (technically, the `assembly` tells the EVM to go back to the offset we used to extract the `s` value, but instead start 1 byte over and extract 32-bytes from that position; once that’s done, the EVM uses `bitwise` `AND` operations [with `0xfff...` values] to mask the upper `248` bits, leaving 1 byte [`8 bits`] remaining, which is our `v` value). 

This is reflected in the assembly code block of the `checkSignatures` function below:

````solidity
assembly {
    let signaturePos := mul(0x41, pos)
    // Load 'r' from the signature
    r := mload(add(signatures, add(signaturePos, 0x20)))
    // Load 's' from the signature
    s := mload(add(signatures, add(signaturePos, 0x40)))
    // Load 'v' from the signature
    // Solidity does not support mload8, so we use mload and mask with 0xff
    // because we only want the last byte of the 65-byte signature (v is 1 byte)
    v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
}
````

After that block is executed, the variables `v`, `r` and `s` are pushed to the top of the stack (with `v` at the top, followed by `s` and `r`). 

This is where things get crucial.

![image](https://github.com/user-attachments/assets/e7da338e-5277-4aa5-8136-353bd0002333)

>    *Before we get into why - let’s observe that the value of that parity byte for the first extracted signature for this process is* `0x1f`, *which is* `31` *in decimal*. 

![image](https://github.com/user-attachments/assets/5934dda1-0ed9-4a74-a4f2-5b05c3da71d7)

At the conclusion of the `signatureSplit` operations, the EVM initiates a new sub-context in preparation for sending data to the `0x01` `ecrecover` precompile contract on Ethereum for address recovery and validation. 

The corresponding line of code in the Gnosis Logic Contract that’s triggered here is: `currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash), v-4, r, s);`. 

#### EVM Hash Mutation

The **biggest issue here at this point** is the erroneous execution of the `PUSH32` opcode instruction (which is attached to the value `0x19457468657265756d205369676e6564204d6573736167653a0a333200000000`). That gets placed at the offset `0x402`.  

![image](https://github.com/user-attachments/assets/ea0b868d-8cab-44fd-8f0a-70abcae560e6)

After the `“\x19Ethereum Signed Message:\n32"` prefix is added (which is the `0x194574..` fixed hexadecimal value that was pushed via the `PUSH32` opcode that we observed), the next element that gets appended is `0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8` (remember that was the value of `txHash` which we covered earlier). 

While this isn’t seen in the actual Solidity code, if we break down the contract to its opcode equivalent or equivalent `Yul` representation, we can see that the contract does indeed possess a coded routine that dictates that the `EIP-191` message should be pushed on to the top of the stack. To be more clear about my statement that ‘’this isn’t seen in the actual Solidity code“ - its worth noting that instead of representing this statement as its 32-byte hexadecimal value in the code, its displayed by its `ASCII` representation (`\x19Ethereum Signed Message:\n32`) . 

Oddly enough, the `EIP-712` example actually warns against this particular instance. Specifically, it states: “*The Solidity expression* `keccak256(someInstance)` *for an instance* `someInstance` of a struct type `SomeStruct…` *currently evaluates to the* `keccak256` *hash of the memory address of the instance. This behavior should be considered dangerous*…*it will fail determinism and/or injectiveness*.”

A true cryptographic hash like Keccak‑256 maps arbitrary‑length data to 32 bytes. By the pigeonhole principle, it **cannot** be strictly injective over an infinite input space—collisions *must* exist, though they are computationally infeasible to find.

What EIP‑712 cares about is that **the encoding step is injective** (no two distinct structured inputs ever produce the same byte string), *before* you feed that string into the hash.

**To get a better understanding, let’s walk down how we got here in the first place**: 

1. The first value we obtained in this execution trace from EVM operations was for the variable, `safeTxHash` in the `encodeTransactionData` function. The value for that variable is: `0xea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0` (*note this is a* `keccak256` *hash*).

2. That value was then included within the `return` statement for that same function (`encodeTransactionData`): `abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, safeTxHash)`. The execution of that line of code for the hacked transaction is what yielded the value: `0x1901b3ded2bdbff5db1a87f6d551fa256e9f2bd6517a3bb84f4c2ea863fb3a5596220xea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0`. This is the `bytes memory` string return dictated by the `encodeTransactionData` function. **This value is later assigned to the** `txHashData` variable within the `execTransaction` function. 

3. Moving forward to the `execTransaction` function, we observed (both in the `EVM` and in code), that the `txHashData` variable gets hashed with `keccak256` to yield the value for `txHash`. This transformation is governed by this statement in the `execTransaction` function:`txHash = keccak256(txHashData)`, which us the following value for the variable `txHash`: `0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8`. **This is supposed to be the message hash right here**. If we were to look at the logs for the hacked transaction, we would **see this hash in the log data**. However, **this is not the hash that the transaction was verified against**. 

4. The hash mutation occurs as we move forward through the `execTransaction` function routine, taking us to the `checkSignatures` function, which is a function that takes the following arguments: `checkSignatures(txHash, txHashData, signatures)`. 

5. Within that function loop, there is a `PUSH32` opcode that pushes an **EIP-191** prefix to the top of the stack for some reason (even though the other EVM type was already digested, constructed, prepended and concatenated with encoded message data before being `keccak` hashed, which is a major deviation from standard practice). If we take a careful look at the code in this area, we can see that the variable `dataHash` is invoked in: `currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s)`. Based on the code notes as well as the EIPs (`EIP191` and `EIP712`) dictating specifications for these signature standards, it is clear that this augmented signature verification deviates from intended deployment. Specifically, the `keccak256` hash output of a valid `EIP-712` signature **should not be nested within another Ethereum Signed Message construction** (especially one that leaps from `signed_typedData v4` to `personal_sign` (`EIP-191`).

6. Once the value `0x19457468657265756d205369676e6564204d6573736167653a0a3332` was pushed to the top of the stack (via the `PUSH32` opcode instruction we identified earlier), the EVM proceeds to take the `txHash` we obtained a short while ago (under the `execTransaction` function) which, itself is the product of an `EIP-712` signed message, to create a **nested** hash within the `EIP-191` signature standard.  

7. Thus, the next value that is pushed (and concatenated with the `personal_sign` prefix) is: `b3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8`, resulting in the following 60 byte concatenated value: `0x19457468657265756d205369676e6564204d6573736167653a0a3332b3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8`

8. A bit later in the EVM, a `keccak256` operation is performed on that value (with the `0x1945` prefix), which manifests this 32-byte string: `0x28eddb7e7d1dca66673b339ca554c63603dede0512d6da0300cf782f68a8a260`. This value is worth **paying special attention to** because **that is the hash that the signatures are actually verified against** (not the transaction hash that we can see in the emitted logs in the hack transaction’s receipt). 

Below are illustrations directly from the EVM that show the entire process described above in an instruction-by-instruction sequence in the EVM: 

![image](https://github.com/user-attachments/assets/a81271c1-a583-4323-9048-fc1252779762)

![image](https://github.com/user-attachments/assets/e87f3799-c8f3-4ee8-bcf5-a8c7243d6378)

![image](https://github.com/user-attachments/assets/60d97ac7-01ab-4052-b20b-c292fa0308fc)

![image](https://github.com/user-attachments/assets/706a079c-732d-49c7-a1fd-229345a0e5b1)

![image](https://github.com/user-attachments/assets/0aff9503-d3df-428e-b18f-d62cb7fb730f)

![image](https://github.com/user-attachments/assets/d759538b-a104-4706-b9ae-40b0e4b22470)

![image](https://github.com/user-attachments/assets/d71b61ba-0a83-445a-8703-ca67f3dee8b4)

![image](https://github.com/user-attachments/assets/9c54f05a-6284-4190-a424-293a0a4a9860)

#### Understanding EIP-191 vs. EIP-712

Both EIPs (*Ethereum Improvement Proposals*) represent different signature standards for Ethereum.

For more explicit documentation on this signature type - [check out this note here](https://mau-eth.gitbook.io/mau/ethereum-improvement-proposals/eip-191). As noted in the documentation, “*Before* `EIP-191`, *Ethereum already had a defect standard for signing messages which involved prefixing messages with a known string* (`\x19Ethereum Signed Message:` followed by the message length). *However, this was limited in flexibility and didn’t cover various use-cases that applications required.* `EIP-191` *aimed to provide a more structured and flexible way to sign different types of data.*”

Also, “`EIP-191` *introduced versioning to the structure of signed data. It allowed for different types of structures, each identified by a version byte*.” 

The format of a signed message under `EIP-191` is:

-   `0x19 <version specific data> <data to sign>`. 
-   `0x19 <version specific data> <intended validator address> <data to sign>` 

##### How Did This Hash Mutation Occur?

The signature standard for this contract uses calls to the precompile EVM address (`0x01`) for `ecrecover` operations. However, taking a close look at the code underneath the `checkSignatures` function makes the source of this strange fork in the contract’s validation logic readily apparent.  

Specifically, the code reveals that the values given to the `ecrecover` precompiled contract for address recovery (from the `signature`) are contingent on a piece of the `signature` data type that has no bearing on the legitimacy of the actual signatures (i.e., whether they are validly formed / represent an actual signature or not etc.). 

For clarity’s sake, let’s take a look at the `checkSignatures` function from the code one more time (posted below): 

````solidity
  function checkSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures, bool consumeHash)
        internal
    {
        // Load threshold to avoid multiple storage loads
        uint256 _threshold = threshold;
        // Check that a threshold is set
        require(_threshold > 0, "Threshold needs to be defined!");
        // Check that the provided signature data is not too short
        require(signatures.length >= _threshold.mul(65), "Signatures data too short");
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < _threshold; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            // If v is 0 then it is a contract signature
            if (v == 0) {
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint256(r));

                // Check that signature data pointer (s) is not pointing inside the static part of the signatures bytes
                // This check is not completely accurate, since it is possible that more signatures than the threshold are send.
                // Here we only check that the pointer is not pointing inside the part that is being processed
                require(uint256(s) >= _threshold.mul(65), "Invalid contract signature location: inside static part");

                // Check that signature data pointer (s) is in bounds (points to the length of data -> 32 bytes)
                require(uint256(s).add(32) <= signatures.length, "Invalid contract signature location: length not present");

                // Check if the contract signature is in bounds: start of data is s + 32 and end is start + signature length
                uint256 contractSignatureLen;
                // solium-disable-next-line security/no-inline-assembly
                assembly {
                    contractSignatureLen := mload(add(add(signatures, s), 0x20))
                }
                require(uint256(s).add(32).add(contractSignatureLen) <= signatures.length, "Invalid contract signature location: data not complete");

                // Check signature
                bytes memory contractSignature;
                // solium-disable-next-line security/no-inline-assembly
                assembly {
                    // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                    contractSignature := add(add(signatures, s), 0x20)
                }
                require(ISignatureValidator(currentOwner).isValidSignature(data, contractSignature) == EIP1271_MAGIC_VALUE, "Invalid contract signature provided");
            // If v is 1 then it is an approved hash
            } else if (v == 1) {
                // When handling approved hashes the address of the approver is encoded into r
                currentOwner = address(uint256(r));
                // Hashes are automatically approved by the sender of the message or when they have been pre-approved via a separate transaction
                require(msg.sender == currentOwner || approvedHashes[currentOwner][dataHash] != 0, "Hash has not been approved");
                // Hash has been marked for consumption. If this hash was pre-approved free storage
                if (consumeHash && msg.sender != currentOwner) {
                    approvedHashes[currentOwner][dataHash] = 0;
                }
            } else if (v > 30) {
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
            } else {
                // Use ecrecover with the messageHash for EOA signatures
// ...[rest of the code logic]
````

Within the conditional blocks (right at the end), we can see one conditional (for EOA signatures), which dictates that: `if v > 30, then: currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s).` The other `else` block below that one (*which only executes if that prior statement’s conditional has not been met*), stipulates: `currentOwner = ecrecover(dataHash, v, r, s)`. 

##### Reviewing Gnosis Safe Documentation on Signatures

>   *To get a better idea of what in the world is actually going on, visiting the Gnosis Safe documentation felt like a prudent decision*. 

>   *If you’re also interested in scouring their documentation as you follow along, go ahead and* [visit this link here](https://docs.safe.global/sdk/protocol-kit/guides/signatures/transactions).

The documentation located at the link above gives directives on how signature are obtained through the official Safe SDK. Even though it is not entirely known how the owners of the Bybit exchange were providing signature verifications *(at the time of the hack or whenever the malicious hack signature was obtained* [if it was obtained at all; more on that later]), the SDK is still a good starting point for us to get a more thorough understanding of the internals of signature creation and validation within the Safe ecosystem.

Specifically, the Safe documentation states that owners of a Safe can leverage their SDK (which can be installed with the `npm` command: `yarn install @safe-global/protocol-kit`), by utilizing the `createTransaction` method from the Protocol Kit. 

Assuming the correct `npm module` has been downloaded (in an adequate environment), Safe provides the following code as a template one can use for crafting `EIP-712` compatible signatures (*which would be most appropriate for this type of transaction since it encompasses the kind of struct that the standard was created to provide transparency for*). 

Here is the `javascript` example below: 

```javascript
// Create a transaction to send 0.01 ETH
const safeTransactionData: SafeTransactionDataPartial = {
  to: '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1',
  value: '100000000000000000', // 0.01 ETH
  data: '0x'
}

let safeTransaction = await protocolKit.createTransaction({
  transactions: [safeTransactionData]
})
```

Per the documentation, “*The returned* `safeTransaction` *object contains transaction data* (`safeTransaction.data`) *and a map of the owner-signature pairs* (`safeTransaction.signatures`). *The structure is similar to the* `EthSafeMessage` *class but applied for* **transactions instead of messages.**” 

That last sentence is critical. The key difference between the `EIP-191` and `EIP-712` standards is that they create **domain separation** for signatures. To be more clear, domain separation does not just involve ensuring that transactions cannot be repurposed on different EVM-compatible chains. This concept applies when it comes to ensuring that signatures: (a) from this same group of owners targeting another Safe cannot be submitted for this one instead (b) signatures over **messages** get handled differently than signatures over **transaction data** (to reduce replay attacks and potential exploits/vulnerabilities like the one we’ve been exploring throughout this report thus far). 

#### Understanding the Dangers of Non-Injective Encoding in EIP-712

The code below serves as a boilerplate illustrating how the deterministic property of EIP-712 can be subverted: 

    keccak256(someStruct)

>   ^^ This hashes the memory pointer (i.e. the address where the struct lives), not its contents. 

    keccak256(abi.encode(someStruct))

>   ^^ Whereas this hashes the actual field values.

    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    
    contract StructHashDemo {
        struct SomeStruct {
            uint256 x;
            uint256 y;
        }
    
        /// @notice Hashes the struct by passing it directly to keccak256(...)
        /// @dev This currently hashes the pointer (memory address) of `s`, not its contents.
        function pointerHash(SomeStruct memory s) public pure returns (bytes32) {
            return keccak256(s);
        }
    
        /// @notice Hashes the struct by ABI‑encoding its contents first
        /// @dev This is the safe, deterministic, injective approach.
        function contentHash(SomeStruct memory s) public pure returns (bytes32) {
            return keccak256(abi.encode(s));
        }
    
        /// @notice Compare four hashes:
        ///         h1 = keccak256(a)
        ///         h2 = keccak256(b)
        ///         h3 = keccak256(abi.encode(a))
        ///         h4 = keccak256(abi.encode(b))
        /// @dev Typically you'll see h1 != h2 (different memory slots) but h3 == h4.
        function compare() external pure returns (
            bytes32 h1,
            bytes32 h2,
            bytes32 h3,
            bytes32 h4
        ) {
            SomeStruct memory a = SomeStruct({ x: 123, y: 456 });
            SomeStruct memory b = SomeStruct({ x: 123, y: 456 });
    
            // Pointer‑based hashes (non‑injective / non‑deterministic):
            h1 = pointerHash(a);
            h2 = pointerHash(b);
    
            // Content‑based hashes (injective within this type):
            h3 = contentHash(a);
            h4 = contentHash(b);
        }
    }

What you’ll observe when you call compare()

-   `h1 != h2` 
-   `h3 == h4` 

The function `pointerHash` is just pointing to a location in memory and that’s what the `keccak256` operation is being performed on. Since `h1` and `h2` live in different memory slots, the resulting hash will be different for them even though they possess the same exact data. 

`contentHash` provides us with the same result for `h3` and `h4` because using the convention, `keccak256(abi.encode(s))` ensures that the members of the struct, specifically, are being hashed. Thus if `h3` and `h4` contain the same members aligned in the same order, the resulting hash for the both of them should be the same. **This** is the principle of injectiveness that `EIP-712` has to possess to be effective. 

#### Applying This Concept to the Gnosis Safe Code

The firm, ‘Runtime Verification’ performed a rigorous formal specification of this Gnosis Safe contract, [which can be found online here](https://github.com/runtimeverification/verified-smart-contracts/wiki/GnosisSafe-Formal-Verification). We’re going to use that as our reference for understanding how the Gnosis contracts work on a more granular level.

Getting a precise understanding of exactly how the `return` data for the `encodeTransactionData` function and others **should perform** will allow us to better understand the designed workflow. This can be obtained from the actual `K code` specification file, [which can be found here](https://github.com/runtimeverification/verified-smart-contracts/blob/master/gnosis/gnosis-spec.ini). 

Check out the header comment below: 

```ini
[encodeTransactionData-internal]
; output = bytes32(32) bytes32(66) bytes1(0x19) bytes1(0x1)
           bytes32(DOMAIN_SEPARATOR) bytes32(SAFE_TX_HASH) bytes30(0)
; size = 160
```

As seen above, this results in an output that produces: 

-   One `32` byte length slot = `0x000...042` (`66` in decimal). 
-   `0x19` byte (prepended) 
-   `0x01` (version byte; also prepended)
-   `bytes32(DOMAIN_SEPARATOR)`
-   `bytes32(SAFE_TX_HASH)` (hash of the inner struct) 
-   30 bytes of zero padding to fill out a total payload of `66 bytes`. 

The resulting size for the word on the stack (for this output) = `160 bytes` on the stack (equivalent of 5 slots since `160/32=5`). 

**How the** `encodeTransactiondata` **Function is Encoded**

In the written pdf for the formal specification and also in its `K code` it is indicated that whenever `encodeTransactionData` is called internally (which it almost always should be), the members of the transaction’s struct (i.e., `to`, `amount`, `data`, `operation`…`et.al`) are evaluated in reverse order. 

```ini
wordStack:
  NONCE : REFUND_RECEIVER : GAS_TOKEN : GAS_PRICE : DATA_GAS
  : SAFE_TX_GAS : OPERATION : DATA_LEN_LOC : VALUE : TO
  : RETURN_LOC : WS
    => RETURN_LOC : INIT_USED_MEM_PTR +Int 384 : WS
```

`RETURN_LOC` is where the caller expects the byte array’s `offset` and `INIT_USED_MEM_PTR + 384` points to the updated free-memory pointer location after writing `66` bytes to it plus alignment. The written formal specification states that, “*the memory stores the* `data` *buffer starting at the location* `DATA_LOC`, *where it first stores the size of the bugger, followed by the actual buffer bytes.*” 

As noted further on in the specification, “`SAFE_TX_HASH` *is the result of* `abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), operation, safeTxGas, dataGas, gasPrice, gasToken, refundReceiver, _nonce)`, *where each argument is 32-byte aligned with zero padding on the left*.” 

That’s what **encodes** the contents of whatever transaction needs to be signed when this function is called. However, that gets slotted within the entirety of the function’s `return` value. 

`````
|<- 32 ->|<- 1 ->|<- 1 ->|<-      32      ->|<-    32    ->|
+--------+-------+-------+------------------+--------------+
|   66   |  0x19 |  0x01 | DOMAIN_SEPARATOR | SAFE_TX_HASH |
+--------+-------+-------+------------------+--------------+
^        ^               ^                  ^              ^
|        |               |                  |              |
OUT_LOC  OUT_LOC + 32    OUT_LOC + 34       OUT_LOC + 66   OUT_LOC + 98
`````

>   *The* `SAFE_TX_HASH` value (which is the encoded transaction), *is slotted next to the* `DOMAIN_SEPARATOR` *which is a fixed value for transactions of this nature. Next to that* (on the left) *are the version bytes* (`0x19` & `0x01`), *preceded by a 32-byte string ending in the hexadecimal for* `66` (0x42). 

Curiously, if the function gets **called externally**, then it provides a return value that gets encoded as thus: 

```
|<- 32 ->|<- 32 ->|<- 1 ->|<- 1 ->|<-      32      ->|<-    32    ->|<- 30 ->|
+--------+--------+-------+-------+------------------+--------------+--------+
|   32   |   66   |  0x19 |  0x01 | DOMAIN_SEPARATOR | SAFE_TX_HASH |    0   |
+--------+--------+-------+-------+------------------+--------------+--------+
```

>   According to the specification, “*Here, the prefix (the first 32 bytes) and the postfix (the last 30 bytes) are attached. The prefix is the offset to the start of the result buffer, and the postfix is the zero padding for the alignment.*”

When this value is invoked later on in the code (under the `checkSignatures` routine), the code does not properly redact the `0x19` and `0x01` prefixes from the `return` value from the `encodeTransactionData` function. 

Remember, in the actual Solidity code, `txHashData` is **not** the equivalent of the `keccak256` hash of the `encodeTransactionData` `return` statement. 

````solidity
// in execTransaction(...)
bytes memory txHashData = encodeTransactionData( … );
nonce++;
bytes32 txHash = keccak256(txHashData);
checkSignatures(txHash, txHashData, signatures, true);
````

As we can see above, only `txHash` is the `keccak256` hashed output of `txHashData`. 

Most notably, the `checkSignatures` function is invoked at the bottom of the code excerpt above with the following arguments: `checkSignatures(txHash, txHashData, signatures, true)`. However, this function is defined contract-wide as: `function checkSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures, bool consumeHash)`. 

One guess for why there was confusion on the part of the Gnosis Safe developers as to **what value** needed to be passed to the `v >30` conditional loop could be due to the shifted naming convention between the arguments that `checkSignatures` takes in the `execTransaction` and the argument names given the provided signature for the function (both `execTransaction` and `checkSignatures` are defined contract-wide under `GnosisSafe.sol`). 

Specifically the function signature provided is: `function checkSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures, bool consumeHash)`. It's not immediately apparent what `bytes32 dataHash` denotes. However, in the code notes above (in the deployed code on the blockchain), the authors write, `@param datHash Hash of the data (could be either a message hash or a transaction hash)` and `@param data That should be signed (this is passed to an external validator contract)`. 

Now we can better assess the issue in the following lines of code: 

`````solidity
else if (v > 30) {
    // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
    currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
} else {
    // Use ecrecover with the messageHash for EOA signatures
    currentOwner = ecrecover(dataHash, v, r, s)

`````

In the conditional `else` statement from above provides the correct pathway for `EIP-712` validation. 

However, the first conditional statement is where havoc exists. The statement, as its written is: `currentOwner = ecrecover(keccak256(abi.encodePacked("\x19 Ethereum Signed Message:\n32", dataHash)), v-4, r, s)`. 

#### Proving the Execution of This Transaction Violates K-Code (KEVM) and Formal Specification

Below is the code for the `transferToken` function that exists within the flattened Gnosis logic contract (`1.1.1`). 

```solidity
function transferToken (
        address token,
        address receiver,
        uint256 amount
    )
        internal
        returns (bool transferred)
    {
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", receiver, amount);
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let success := call(sub(gas, 10000), token, 0, add(data, 0x20), mload(data), 0, 0)
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, returndatasize()))
            returndatacopy(ptr, 0, returndatasize())
            switch returndatasize()
            case 0 { transferred := success }
            case 0x20 { transferred := iszero(or(iszero(success), iszero(mload(ptr)))) }
            default { transferred := 0 }
        }
    }
}
```

That function is defined in `contract SecuredTokenTransfer`. This contract is then inherited by the main `GnosisSafe.sol` contract. It is included as part of the `handlePayment` function. The function definition for `handlePayment` begins with the following statement: `bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", receiver, amount)`. 

Let’s recap the values of the `execTransaction` struct:

This results in the `encodeTransactionData` function that contains the following values in the struct: 

| Parameter        | Value                                                        | Description                                     |
| ---------------- | ------------------------------------------------------------ | ----------------------------------------------- |
| `to`             | `0x96221423681a6d52e184d440a8efcebb105c7242`                 | Target contract address                         |
| `value`          | `0`                                                          | No ETH sent                                     |
| `data`           | `0xa9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be29695160000000000000000000000000000000000000000000000000000000000000000` | Encoded call data (`transfer(address,uint256)`) |
| `operation`      | `1`                                                          | DelegateCall operation                          |
| `safeTxGas`      | `45746`                                                      | Gas allocated for safe transaction execution    |
| `baseGas`        | `0`                                                          | Base gas cost                                   |
| `gasPrice`       | `0`                                                          | Gas price                                       |
| `gasToken`       | `0x0000000000000000000000000000000000000000`                 | Token used for gas (0 for ETH)                  |
| `refundReceiver` | `0x0000000000000000000000000000000000000000`                 | Refund receiver address                         |
| `_nonce`         | `42`                                                         | Transaction nonce                               |

If we extract the `data` parameter, we get the following: `0xa9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be29695160000000000000000000000000000000000000000000000000000000000000000`. 

In a large percentage of `execTransaction` calls that have been made on a specific set of Gnosis proxy deployments we've been examining, calldata imitating a nested transfer function can be seen. In this case, the `transfer` signature + `address` (the `bdd..` value we see starting at the 33rd byte), followed by the `uint256` total (`0000`) all seem to mimic the same parameters that the `transferToken` function takes as arguments.

The following workflow shows the role the `transferToken` function plays in the contract whenever there is a nested `transferToken` call in the transaction data: 
```
User → execTransaction → handlePayment → transferToken
````

The data parameter is consistently 68 bytes because it follows Ethereum's ABI encoding rules for the `transfer(address,uint256)` function:

```
0xa9059cbb + <32 bytes padded address> + <32 bytes uint256>
```

Breaking it down:
- `0xa9059cbb`: 4 bytes - Function selector for `transfer(address,uint256)`
- Next 32 bytes: The padded recipient address
- Last 32 bytes: The token amount as a uint256

This 68-byte structure is standard across ERC20 token transfers and follows the EVM's parameter encoding requirements, which pads all values to 32-byte words.

Looking at the formal specification and the actual implementation, `encodeTransactionData` follows EIP-712 typed structured data hashing:

1. Creates a structured hash using `SAFE_TX_TYPEHASH` and all transaction parameters
2. Combines this with domain separator following EIP-712 standard
3. **Returns the bytes that need to be signed by owners**. 

The `transferToken` implementation uses inline assembly for several reasons:

1. **Gas optimization**: Direct `call` opcode usage is more efficient than higher-level approaches
2. **Return value handling**: The assembly block carefully handles different token return value behaviors
3. **Gas stipend**: The `sub(gas, 10000)` reserves gas for the remaining execution

The function adapts to different ERC20 implementations by checking:
- No return data (old tokens): Success depends on the call success
- 32-byte return (standard): Success requires both call success and non-zero return value
- Anything else: Considered failure

##### EIP-712 Encoding Process

According to section 4.1 of the Gnosis Safe formal specification, the `encodeTransactionData` function produces EIP-712 compliant encoded data. This creates a structured hash that's used for signature verification.

```solidity
bytes32 safeTxHash = keccak256(
    abi.encode(
        SAFE_TX_TYPEHASH,
        to,                     // 0x96221423681a6d52e184d440a8efcebb105c7242
        value,                  // 0
        keccak256(data),        // Hash of the token transfer data
        operation,              // 1 (DelegateCall)
        safeTxGas,              // 45746
        baseGas,                // 0
        gasPrice,               // 0
        gasToken,               // 0x0000...
        refundReceiver,         // 0x0000...
        _nonce                  // 42
    )
);
```

Note that according to the specification (section A.1.3), the `data` parameter is hashed separately with `keccak256` before being included in the `abi.encode` operation. This ensures fixed-length encoding regardless of the data size.

The token transfer data (`0xa9059cbb...`) embedded in our calldata is the `data` parameter being passed to `execTransaction`. When `execTransaction` runs, it will:

1. Call `encodeTransactionData` with all parameters.
2. Hash the result to get `txHash.`
3. Verify that there are sufficient valid signatures for this hash.
4. Execute the actual token transfer if signatures are valid.

According to the specification (section 3.4.2), this encoding method ensures that signatures can be safely checked and prevents various replay attacks by including the nonce and contract-specific domain separator.

A better understanding of how the signature verification flow works can be found in a `yul` representation of the logic contract. For convenience, this has been uploaded as a `gist` [here](https://gist.github.com/FoobarProtocol/fe35110614a990871c4f20359d8bc540).

With our breakdown of the `Yul` code, we’re going to start with function `func_0x59f0`. 

**1. Analysis of `func_0x59f0`**

This function acts as a specialized dispatcher for making an external call, specifically formatted as an **ERC20 `transfer` call.**

-   **Inputs:**
    -   `_328`: Likely the `amount` for the transfer (uint256).
    -   `_329`: Likely the `recipient` address for the transfer (address).
    -   `_330`: The `target contract address` (the ERC20 token contract) to call (address).
    -   `_331`: Appears unused in this specific function's logic.
-   **Steps:**
    1.  **Memory Allocation & Setup:** Reads the free memory pointer (`mload(0x40)`). It then allocates some temporary space (`_333 = start_ptr + 0x24`).
    2.  **Store Recipient Address:** Stores the input `_329` (masked to 20 bytes) into memory at `_333`.
    3.  **Store Amount:** Stores the input `_328` into memory 32 bytes after the recipient address (`_334`).
    4.  **Prepare Call Data Structure:**
        -   Reads the *actual* free memory pointer again (`_336`). This is where the final `bytes` structure for the call will begin.
        -   Calculates the length of the data body (recipient + amount), which is 20 + 32 = 52 bytes, but EVM works in 32-byte words, so it's treated as 64 bytes potentially. The calculation `sub(sub(_335, _336), 0x20)` results in `0x44` (68 decimal). **It stores the length `68` at the free memory pointer `_336`.**
        -   Updates the global free memory pointer (`mstore(0x40, _335)`).
    5.  **Force Function Selector:**
        -   `_337 := add(_336, 0x20)`: Points to the memory location *immediately after* the length word. This is the start of the actual call data body.
        -   `_338 := mload(_337)`: Loads the 32 bytes currently at that location.
        -   `mstore(_337, or(and(_338, 0x...ffff), and(not(0x...ffff), 0xa9059cbb...)))`: This is the crucial manipulation. It uses bitwise operations:
            -   `and(_338, 0x...ffff)`: Keeps the lower 20 bytes of whatever was loaded (`_338`). Assuming the recipient address (`_329`) was intended to be part of the final payload, this preserves it.
            -   `and(not(0x...ffff), 0xa9059cbb...)`: Takes the constant `0xa9059cbb0000...` (the ERC20 `transfer` function selector, padded) and zeroes out its lower 20 bytes.
            -   `or(...)`: Combines the two, effectively overwriting the upper bytes (including the first 4 bytes) with `0xa9059cbb` while keeping the lower 20 bytes (the recipient address).
        -   **Result:** The memory at the start of the call data body now *definitively* begins with the `transfer` function selector, followed by the recipient address. The amount (`_328`) is stored in the next word.
    6.  **Execute External Call:**
        -   `_339 := mload(_336)`: Reloads the length (68).
        -   `_340 := call(...)`: Makes an external `call` to the target contract `_330` with 0 ETH value. The data sent starts *after* the length word (`add(_336, 0x20)`) and has length `_339` (68). It leaves a gas stipend (`0x2710` = 10000 gas). The success/failure (1 or 0) is stored in `_340`.
    7.  **Handle Return Data:** Copies any data returned by the external call into memory.
    8.  **Return Value Logic:**
        -   If no data was returned (`returndatasize == 0`), it returns the call's success status (`_340`).
        -   If 32 bytes were returned (`case 0x20`), it checks if *both* the call succeeded (`_340`) *and* the returned 32-byte value (`_344`) is non-zero. This is typical for checking a `bool true` return value from an ERC20 transfer.
        -   For any other return data size, it implicitly returns 0 (failure).
-   **Purpose:** `func_0x59f0` is a low-level utility function within the Gnosis Safe logic specifically designed to execute an ERC20 `transfer`. It manually constructs the `calldata`, forces the correct function selector, makes the call, and interprets the success based on standard ERC20 return patterns. It's likely used internally, for example, within the `handlePayment` function (`func_0x50ca`) when gas refunds are paid using ERC20 tokens.

**2. Other Interesting Aspects of `logicyul.txt`**

This file represents the blueprint of the Gnosis Safe 1.1.1 contract at the EVM level.

-   **Main Dispatcher (Entry Point Logic):** The code starting around `let _42 := shr(0xe0, calldataload(0x0))` is the main function selector dispatcher. It takes the first 4 bytes of the incoming transaction data, compares it against known function selectors using `gt` (greater than) and `eq` (equals) in a series of nested `if` blocks (often forming a binary search tree for efficiency), and jumps to the corresponding internal function (e.g., `func_execTransaction`, `func_addOwnerWithThreshold`).
-   **`func_fallback()`:** Handles calls that don't match any known selector or plain ETH transfers. It checks if a specific storage slot (derived from hash `0x6c9a...d5`) contains a fallback handler address. If so, it forwards the call (`delegatecall` or `call` - looks like `call` here: `call(gas(), _61, 0x0, ...)`). This allows extending Safe functionality.
-   **`func_0x470a` (Implementation of `checkSignatures`):** This is a highly complex but critical function.
    -   It iterates based on the `threshold`.
    -   It correctly parses `v`, `r`, `s` from the packed `signatures` bytes array.
    -   It explicitly handles the different signature types based on `v`:
        -   `v == 0`: Contract signatures (EIP-1271). Performs checks on the signature data location within the `signatures` bytes array and makes a `staticcall` to the contract's `isValidSignature` function.
        -   `v == 1`: Approved Hashes. Checks `msg.sender` or the `approvedHashes` mapping. Includes logic for `consumeHash`.
        -   `v > 30`: EIP-191 (`eth_sign`) compatible signatures. **Crucially, it calculates `keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash))`** (`_144` to `_151`) and then makes a `staticcall` to the `ecrecover` precompile (address `0x1`) using `v - 4`.
        -   `else` (`v == 27` or `v == 28`): Standard EOA signatures. Makes a `staticcall` to the `ecrecover` precompile using the raw `dataHash`.
    -   It performs owner validation checks (ordering `currentOwner > lastOwner`, existence `owners[currentOwner] != address(0)`, not sentinel).
-   **`func_execTransaction()`:** Orchestrates the main transaction execution flow. It involves scopes (`{ ... }`) likely translated from Solidity's variable scoping. It shows the sequence: call internal `encodeTransactionData` logic, increment nonce, calculate `txHash`, call internal `checkSignatures` logic (`func_0x470a`), perform the main `execute` (via internal `call`/`delegatecall`), handle payment (`func_0x50ca`), and emit events.
-   **`func_encodeTransactionData()` / `func_getTransactionHash()`:** These implement the EIP-712 hashing logic, including getting the `domainSeparator` (from `sload(0x6)`), hashing the `data` parameter (`keccak256(data)`), encoding all parameters (`abi.encode` logic), hashing that (`safeTxHash`), packing with prefix+separator (`abi.encodePacked`), and finally hashing *that* result for `getTransactionHash`.
-   **Storage Access:** Uses standard Yul patterns for accessing storage mapping slots: `mstore` address and slot index (constants like `0x1` for modules, `0x2` for owners, `0x8` for approvedHashes) into memory `0x0` to `0x40`, then `keccak256(0x0, 0x40)` to get the storage key, followed by `sload` or `sstore`.
-   **Safe Math:** Functions `func_0x5938` (multiplication with overflow check) and `func_0x59a1` (addition with overflow check) are likely implementations of SafeMath equivalents.
-   **Owner/Module/Threshold Management:** Functions like `func_addOwnerWithThreshold`, `func_removeOwner`, `func_swapOwner`, `func_enableModule`, `func_disableModule`, `func_changeThreshold` contain the logic for updating the Safe's configuration, usually protected by a check that `caller() == address()` (meaning the call must originate from the Safe itself, typically via `execTransaction`).

The forced function selector in `func_0x59f0` is a specific detail related to reliably dispatching ERC20 transfers internally.

What the developers are assuming: 

1.   That the `dataHash` is not actually returning the actual hashed value of the transaction data. Whoever coded this skipped a step ahead here. The `0x19 Ethereum Signed Message:\n32"` ASCII prefix is supposed to be hashed at the same time a hash of the **original** **message** is hashed. The authors wrote explicitly in the code that it was their expectation that all signatures with a `v` value of `> 30` appended to it would be `messages` vs. `transactions`. Thus, it stands to reason that the authors meant to enter `data` here instead. 
2.   Even if `data` were entered here, the authors **hard coded** the `0x19` and `0x01` two byte prefix into the `return` statement of every function in the contract that `execTransaction` can access. Thus, even if the `execTransaction` did call the non-hashed version of the transaction's contents, it would still break `EIP-191` specification because it is **not** supposed to iterate over any string that starts with the same null-byte (`0x19`). 
3.   Even if the former two issues were resolved, there’s still the destruction of domain separation (literally) by taking data that was originally purposed as a transaction and then having the contract process it as a regular personal signed message. 

To elaborate a bit more on why #3, by itself, represents a potent attack vector, we’re going to have to explore the differences in how `EIP-191` data is prepared for signing vs. `EIP-712`. 

Below is a chart that breaks down many of the **key critical differences between both signature standards**. 

| **Aspect**                           | **EIP‑191 (Simple Signed Data)**                             | **EIP‑712 (Typed Structured Data)**                          |
| ------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Data Representation & Processing** | Opaque bytes, single-pass hashing:<br>`keccak256("\x19Ethereum Signed Message:\n<len>" + message)` | Structured, typed objects, recursive hashing:<br>`keccak256("\x19\x01" + domainSeparator + hashStruct(type, data))` |
| **Domain Separation**                | Minimal: version byte only (e.g. `0x45`), relies on message content to avoid conflicts | Robust: explicit `domainSeparator` including contract address, chain ID, version → prevents cross‑contract & cross‑chain reuse |
| **Transaction vs. Message Context**  | Treats a transaction payload as opaque data—no field‑level distinctions; users see hex blob | Defines a `Transaction` type with named fields (to, value, data, …); users see structured fields when signing |
| **Presentation to Users**            | Displays raw hex data, giving little semantic context        | Shows human‑readable field names and values, making intent clearer |
| **Scope of Authority**               | Ambiguous—contracts decide how to interpret opaque data      | Clear—typed data and domain parameters tightly bind a signature’s authority to a specific contract, chain, and action |
| **Security Context**                 | No built‑in protection separating on‑chain state changes vs. off‑chain messages | Explicitly separates transaction signatures (state changes) from message signatures (off‑chain intent) |
| **Guardrails (e.g. in Gnosis Safe)** | –                                                            | • Prevents using a token‑transfer signature for a message approval<br>• Prevents replay across different Safe instances<br>• Prevents replay across chains via chain ID |

In either case, the way the Gnosis Safe contract is designed makes it so that **everything** is processed as though it were a signature (unless it's an `approvedHash` or `contract signature`). Otherwise, there is no credible pipeline for verifying a message without that message being processed as a transaction. 

Below, various lines of code are lined up with their `k` code equivalents to add clarity in understanding which `k` invariants are related to a specific area of the code we’re examining. 

Starting with the definition of `safeTxHash`

```solidity
bytes32 safeTxHash = keccak256(
  abi.encode(
    SAFE_TX_TYPEHASH,
    to, value, keccak256(data),
    operation, safeTxGas,
    baseGas, gasPrice,
    gasToken, refundReceiver,
    _nonce
  )
);
```

Which corresponds to the following in the `k` code: 

```ini
SAFE_TX_HASH: keccak(
  #encodeArgs(
    #bytes32(#parseHexWord({SAFE_TX_TYPEHASH})),
    #address(TO),
    …,
    #uint256(NONCE)
  )
)
```

Also the following Solidity code: 

````solidity
domainSeparator = keccak256(
  abi.encode(DOMAIN_SEPARATOR_TYPEHASH, this)
);
````

With its equivalent in `k code`: 

```ini
… 25 : 1 : #bytes32(DOMAIN_SEPARATOR) : …
```

Plus: 

````solidity
bytes memory txHashData = encodeTransactionData(…);
bytes32 dataHash = keccak256(txHashData);
checkSignatures(dataHash, txHashData, signatures, true);
````

Which corresponds to the following in `k code`: 

```ini
TX_HASH_DATA: keccak(
  25          // 0x19
  : 1         // 0x01
  : #encodeArgs(#bytes32(DOMAIN_SEPARATOR), #bytes32(SAFE_TX_HASH))
)
```

In the K specification, the very first parameter to `checkSignatures` is called `TX_DATA_HASH`. Look at the rule handling the successful signature‐check branch under `execTransaction-checkSigs1-gas1` (and its “gas1” variants). You’ll find:

```ini
+requires:
  …
  TX_HASH_DATA: keccak(
    25 : 1 :
    #encodeArgs(
      #bytes32(DOMAIN_SEPARATOR),
      #bytes32({SAFE_TX_HASH})
    )
  )
```

Thus, we’ve verified that this issue is one that does exist validly in Gnosis Safe contracts (versioning all the way up to `1.3.0`) and that the behavior of Gnosis (under the hood) via live EVM replay or simply walking down the documentation and formal specification online validates that this ‘double hashing’ behavior is hard coded into Gnosis Safe contracts (*although it doesn’t seem with the expectation that it would behave the way it is currently*). 

All throughout the code, we’re invoking ````encodeTransactionData```` to iterate over and generate data directly related to the message hashing process itself. 

For convenience, here’s the function below: 

    function encodeTransactionData(...) public view returns (bytes memory) {
        bytes32 safeTxHash = keccak256(
            abi.encode(
              SAFE_TX_TYPEHASH,
              to,
              value,
              keccak256(data),
              safeTxGas,
              baseGas,
              gasPrice,
              gasToken,
              refundReceiver,
              _nonce
            )
        );
        return abi.encodePacked(
          byte(0x19),
          byte(0x01),
          domainSeparator,
          safeTxHash
        );
    }

Internally, this is what the function does (and returns): 

    abi.encodePacked(
      byte(0x19),            // EIP‑191 version prefix
      byte(0x01),            // EIP‑712 typed‑data version
      domainSeparator,       // keccak256(EIP712Domain(...))
      keccak256(              // “struct” hash
        abi.encode(
          SAFE_TX_TYPEHASH,   // 32‑byte typeHash for Safe transactions
          to,
          value,
          keccak256(data),    // dynamic `bytes` hashed to 32 bytes
          safeTxGas,
          baseGas,
          gasPrice,
          gasToken,
          refundReceiver,
          nonce
        )
      )
    )

The issue manifests itself in the execTransaction function within the scoped sub-routine for deriving the value of bytes32 txHash, where it writes: 

    {
                bytes memory txHashData = encodeTransactionData(
                    to, value, data, operation, // Transaction info
                    safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, // Payment info
                    nonce
                );
                // Increase nonce and execute transaction.
                nonce++;
                txHash = keccak256(txHashData);
                checkSignatures(txHash, txHashData, signatures, true);
            }

That `txHash` variable is what is referenced in the checkSignatures portion of the code - but in the form of the name `hashData`. Additionally, there is no code in the `k code` formal specification that even addresses a case for handling `EIP-191` signatures specifically (perhaps an oversight that may have allowed this attack vector to exist for as long as it has). 

#### Trail of Bits Audit of Meson Fi Identifies the Same Attack Vector

In their [recent audit](https://static.meson.fi/MesonFi-Audit-Report-R3-2022Oct.pdf) of a DeFi project called, ‘Meson Fi’. 

![image](https://github.com/user-attachments/assets/ee3c25d4-f1f6-4987-bc0a-5486f7a0803a)

Below we’re going to see ‘Trail of Bits’ effectively identify the same exact attack vector as the one that exists in the Gnosis Safe contracts currently (spanning across all contract versions): 

![image](https://github.com/user-attachments/assets/2538adc5-6e1d-42b1-83b9-e5a4618482fe)

![image](https://github.com/user-attachments/assets/f6e8796e-1969-4e92-876d-1d8f15d8ac14)

With an estimated difficulty between $2^{60}$ - $2^{70}$ tries, this collision probability falls within the capabilities of a state-based actor like the Lazarus Group.

#### Diving into How Signatures Are Processed via Safe’s Multi-Sigs

When operating multiple different multi-signature Safes or handling a single entity on multiple different chains and/or with the same master account or private key, having **domain separation** built into your contract’s signature validation standard is absolutely critical.

Such a feature would benefit Bybit substantially since the same group of addresses that are listed as owners of their compromised proxy are also listed as owners over 10+ other proxies. 

Below is a short list of some of those proxies (*the word ‘some’ is being used here since it is highly unlikely that this list is exhaustive*): 

1.  `0x72ede922683dc98497317744cd9ee62345462561` (December 12th, 2021)
2.  `0xa7a93fd0a276fc1c0197a5b5623ed117786eed06` (February 9th, 2021)
3.  `0x705199fe234a7a2f1bc8b95dd7d08284c8f467f1` (November 3rd, 2022)
4.  `0x2ebf891f4718eb8367013d8d975a1e5afcae277f` (November 17th, 2022)
5.  `0xd2f0c70ac768cba8c10ee64fc2657ee8c1ca862f` (January 10th, 2023)
6.  `0x6f4565c9d673dbdd379aba0b13f8088d1af3bb0c` (April 3rd, 2023)
7.  `0x0729ff91c188ebc6f290ba4e228cff72ef940044` (August 7th, 2023)
8.  `0x086a8d541febd35bed66a799e08a1799af5f4481` (August 14th, 2023)
9.  `0x089423ad2f9f195a72b28d37c902a1d060586d39` (November 27th, 2023) 
10.  `0x75ae0e74b18290646b5c56c2ff6e58f9e41a9c33` (February 2nd, 2024)
11.  `0xc3350595ed42ebe94556277bc77d257c76065291` (February 2nd, 2024) 

As we noted in the code earlier when we were stepping through our EVM debugger, there must be great care taken (on the part of smart contract developers) to ensure that any and all signature validation logic that they include in smart contracts for either the `EIP-712` or `EIP-191` standards include appropriate **domain separators** and **type hashes** (*contingent on use case*). 

Notably, if we revisit the code for logic contract underpinning the compromised Bybit proxy, we’ll see that these constants are all declared in the code (shown below): 

````solidity
bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = 0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749;

//keccak256(
//"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
//);
bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

//keccak256(
//    "SafeMessage(bytes message)"
//);
bytes32 private constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;
````

>   *Please note that the value for the* `DOMAIN_SEPARATOR_TYPEHASH` *derives from the address of the caller* (since this is a`delegatecall`). *The relevant value for the Bybit proxy can be found in that contract’s storage in* `slot 0x0000000000000000000000000000000000000000000000000000000000000006 `. *That value is*: `0xb3ded2bdbff5db1a87f6d551fa256e9f2bd6517a3bb84f4c2ea863fb3a559622`. *The* `SAFE_TX_TYPEHASH` *value is derived directly from the logic contract, however* (for some reason; that’s how Gnosis decided to set up their proxy orchestration for whatever reason). *Based on the signature validation flow dictated in the logic contract, there are no clear paths for validation that can be observed where this value would be put to use outside of specifically executing the function* `getMessageHash`. *Curiously, even the* `SAFE_MSG_TYPEHASH` *construction has a return statement which reads*: `return keccak256(abi.encodePacked(byte(0x19), byte(0x01), domainSeparator, safeMessageHash)`. 

**Signing the Transaction per Gnosis Safe Docs and the Safe SDK** 

With the above in mind, let’s return to the Gnosis Safe documentation on EOA signature creation and validation in their ecosystem to ensure that this construction is not something that is the product of a purposeful design choice by the team (*as doubtful as that appears currently*). 

According to the SDK docs, “*Once the* `safeTransaction` *object is created, we need to collect the signatures from the signers who will sign it. Following our setup, we will sign a Safe transaction from* `SAFE_3_4_ADDRESS`, *the main Safe account in this guide. To do that, we need to first sign the same transaction with its owners*. `OWNER_1_ADDRESS`, `OWNER_2_ADDRESS`, `SAFE_1_1_ADDRESS`, *and* `SAFE_2_3_ADDRESS`.”

“[The ECDSA signature verification flow] *applies to* `OWNER_1_ADDRESS` *and* `OWNER_2_ADDRESS` *accounts, as both are EOAs. The* `signTransaction` *method takes the* `safeTransaction` *together with a* `SigningMethod` *and adds the new signature to the* `safeTransaction.signatures` *map. Depending on the type of message, the* `SigningMethod` *can take these values*: 

-   `SigningMethod.ETH_SIGN`
-   `SigningMethod.ETH_SIGN_TYPED_DATA_V4`"

Then the following code is presented within the docs as a template that can be used (*or modified & expanded in accordance with the SDK’s specifications*) to collect signatures from requisite signers (*specifically ones that are providing EOA signatures that need to be verified via ECSDA operations like* `ecrecover` [right down our alley since that’s the scenario we’re in and thus, seeking more information about]): 

```javascript
// Connect OWNER_1_ADDRESS
protocolKit = await protocolKit.connect({
  provider: RPC_URL,
  signer: OWNER_1_PRIVATE_KEY
})

// Sign the safeTransaction with OWNER_1_ADDRESS
// After this, the safeTransaction contains the signature from OWNER_1_ADDRESS
safeTransaction = await protocolKit.signTransaction(
  safeTransaction,
  SigningMethod.ETH_SIGN
)

// Connect OWNER_2_ADDRESS
protocolKit = await protocolKit.connect({
  provider: RPC_URL,
  signer: OWNER_2_PRIVATE_KEY
})

// Sign the safeTransaction with OWNER_2_ADDRESS
// After this, the safeTransaction contains the signature from OWNER_1_ADDRESS and OWNER_2_ADDRESS
safeTransaction = await protocolKit.signTransaction(
  safeTransaction,
  SigningMethod.ETH_SIGN_TYPED_DATA_V4
)
```

According to the Safe documentation, executing the above code results in an output akin to the following:

````javascript
EthSafeTransaction {
  signatures: Map(2) {
    '0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1' => EthSafeSignature {
      signer: '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1',
      data: '0x969308e2abeda61a0c9c41b3c615012f50dd7456ca76ea39a18e3b975abeb67f275b07810dd59fc928f3f9103e52557c1578c7c5c171ffc983afa5306466b1261f',
      isContractSignature: false
    },
    '0xffcf8fdee72ac11b5c542428b35eef5769c409f0' => EthSafeSignature {
      signer: '0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0',
      data: '0x4d63c79cf9d743782bc31ad58c1a316020b39839ab164caee7ecac9829f685cc44ec0d066a5dfe646b2ffeeb37575df131daf9c96ced41b8c7c4aea8dc5461801c',
      isContractSignature: false
    }
  },
  data: { ... }
}
````

Notably, the SDK docs confirm that, “*the final part of the signature, either* `1f` *or* `1c`, *indicates the signature type.*”

Two **important notes worth observing from the documentation**: 

1.   EOA signatures (*as evaluated by the Safe in accordance with their most recent/up-to-date documentation*) stipulates that final byte for such signatures (`65th` byte) serve as the ‘’parity” value for the split ECDSA signature (effectively the `v` value). The documentation expands on this idea further by also stipulating the following for `v` values: “`{27, 28} + 4`: *Ethereum adjusted ECDSA recovery byte for* `EIP-191`*signed message*.”
2.   There is another note below the above statement which reads (critically): “*Regarding the* `EIP-191` *signed messages, the* `v` *value is* **adjusted to the ECDSA** `v+4`. *If the generated value is* `28` *and adjusted to* `0x1f`, *the signature verification will fail as it should be* `0x20` (`28+4=32`) *instead*. *If* `v > 30`, *then the default* `v (27, 28)` *was adjusted because of the* `eth_sign` *implementation. This calculation is automatically done by the* `Safe{Core} SDK`.”

That last fact tells us a lot of (important) information. 

**Namely**: 

-   The signature validation and verification process (**in the SDK**) contain instructions for signature verification which deviate from how the Gnosis Safe contracts (*for proxies deployed pointing to implementation addresses using versions* `1.1.1-1.3.0`). 
    -   The current code in the logic contract for Bybit’s compromised proxy stipulates the opposite of what we see specified in the SDK documentation. Specifically, the logic contract’s code says if the value of `v` is **above** `30`, then the that variable should be decremented by `4` (to normalize the resulting signature's parity byte to a value of either `28` or `27`. With this effectively creates is a loop where one may generate a signature whose `v` value ends in `27` or `28`. If that person leveraged the `Safe SDK` to do so, then the parity byte for their signature was automatically incremented by `4` to normalize it to a value of `31` or `32`. However, once those signatures were obtained and submitted to the deployed Safe on-chain (under the `1.1.1` factory standard), those parity bytes were decremented back down to their original values (for the sole purpose of signature verification), **ultimately defeating the purpose of altering the** `v` **value at all**. That last sentence was emphasized to (hopefully) re-emphasize and underscore the fact that this hash mutation **destroys all semblance of domain separation, safety from replay attacks, etc.**
    -   The current Gnosis SDK attempts to **normalize** all signatures to a `v > 30`. In theory, if the contract embodied this same concept, then there would be no room for hash mutations or a variation of what hash are verified against (*that falls outside of the provided conditional options for signature validation*). 
    -   Since the contract’s logic and the SDK’s behavior **contradict one another**, it is **nearly impossible** for us to tell how the signatures were crafted originally. Specifically, the docs tells us, “*the hexadecimal value*, `1f` *equals the decimal number* `31`. *If the decimal value is greater than* `30`, *it indicates that the signature is an* `eth_sign` *signature.*” This is consistent with how a signature with this value is treated by the logic contract. However, the issue here is that we don’t know whether the signatures that possess the value `1f` (`31`) for their parity byte have already had their parity byte augmented by the SDK (which stipulates that a signature with an OG `v` value of `27` or `28` must have this value incremented by `4` to `31` or `32`). In the alternative where a signature was crafted with that value (organically), one must assume (based on the Safe SDK docs), that its parity byte would go **untouched**. Thus, in any case where a signature has been submitted on-chain to the logic contract for Bybit’s compromised proxy, we have no way of telling whether that signature was a legitimate `eth_sign` / `personal_sign` or not.

As an example, the SDK disassembles the following signature `0x969308e2abeda61a0c9c41b3c615012f50dd7456ca76ea39a18e3b975abeb67f275b07810dd59fc928f3f9103e52557c1578c7c5c171ffc983afa5306466b1261f`  to provide users with a better understanding of how to interpret submitted signatures within this ecosystem: 

| Type           | Description             | Bytes | Value                                                        |
| -------------- | ----------------------- | ----- | ------------------------------------------------------------ |
| Hex            | Hex string characters   | 1     | 0x                                                           |
| Signature      | Signature bytes         | 64    | 969308e2abeda61a0c9c41b3c615012f50dd7456ca76ea39a18e3b975abeb67f275b07810dd59fc928f3f9103e52557c1578c7c5c17ffc983afa5306466b126 |
| Signature Type | 1f hex is 31 in decimal | 1     | 1f                                                           |

#### How the Attacker Could Have Leveraged and Exploited This

Looking at the implementation closely:

```solidity
// First function computes and returns the EIP-712 formatted data
function encodeTransactionData(...) public view returns (bytes memory) {
    bytes32 safeTxHash = keccak256(
        abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce)
    );
    return abi.encodePacked(byte(0x19), byte(0x01), domainSeparator, safeTxHash);
}

// Second function hashes the result of the first
function getTransactionHash(...) public view returns (bytes32) {
    return keccak256(encodeTransactionData(...));
}
```

This implementation effectively:
1. Creates the EIP-712 formatted data with prefixes in `encodeTransactionData`
2. Then hashes this complete structure in `getTransactionHash`
3. Then for `v > 30` signatures, would apply the EIP-191 prefix to this hash

This creates an unexpected nesting: `keccak256("\x19Ethereum Signed Message:\n32" + keccak256("\x19\x01" + domainSeparator + safeTxHash))`

What should have happened instead:
1. `encodeTransactionData` should either return only `safeTxHash` or clearly separate the hash from its formatted version
2. `getTransactionHash` should use the appropriate component rather than hashing the complete formatted data

This implementation doesn't match standard wallet signing behavior and could lead to signature verification issues. Specifically:

1. When a user signs with MetaMask using `eth_sign`, the wallet uses the pattern: `keccak256("\x19Ethereum Signed Message:\n32" + message)`
2. The contract expects: `keccak256("\x19Ethereum Signed Message:\n32" + keccak256("\x19\x01" + domainSeparator + safeTxHash))`

These won't match unless wallets are specifically coded to understand this non-standard approach. This oversight might explain why some third-party integrations have had difficulty with Gnosis Safe signature verification, requiring custom signing implementations to match the contract's expectations. 

##### What Are the Contract’s Expectations for This Nested Signature Bug?

According to the contract's logic, these steps should happen in `execTransaction`:

1.   **Transaction Data Encoding**:

`````solidity
bytes memory txHashData = encodeTransactionData(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce);
`````

1.   **Transaction Hash Generation**:

  ```solidity
  txHash = keccak256(txHashData);
  ```

1.   **Signature Verification**:

  ```solidity
  checkSignatures(txHash, txHashData, signatures, true);
  ```

The `encodeTransactionData` function first generates `safeTxHash` and then prepends the EIP-712 domain prefix:

`````solidity
bytes32 safeTxHash = keccak256(abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), operation, ...));

return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, safeTxHash);

`````

Looking at the three distinct hashes (for the hacked transaction):

1. `safeTxHash`: `0xea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0`
   - This is the hash of the malicious transaction parameters.

2. `txHash`: `0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8`
   - This should be the `EIP-712` formatted version of the `safeTxHash`

3. Verification hash: `0x28eddb7e7d1dca66673b339ca554c63603dede0512d6da0300cf782f68a8a260`
   - This is the hash that was actually used during signature verification
   - **Critical point**: This hash is completely unrelated to the other two!

**Discovery**: “*The attackers provided signatures that validated against this substituted hash.*“

#### Outlining the Steps for Finding a Potential ‘Collision’ to Present an ‘Approved’ Malicious TX

Based on what we've learned about the double-prefixing vulnerability, a sophisticated attacker (particularly a state-level actor with significant computing resources) could systematically engineer collisions to compromise Gnosis Safe wallets. Here's how:

1. **Target Transaction Identification**
   - Identify any legitimate transaction that has been signed by enough owners to meet the threshold
   - Let's call this transaction T with its corresponding hash $H(T)$.

2. **Double-Process Hash Calculation**
   - Calculate the double-processed hash `D = keccak256(EIP191_PREFIX + H(T)). `
   - This `D`value is what signatures will be verified against

3. **Malicious Transaction Engineering**
   - Create a malicious transaction M that would benefit the attacker
   - Vary its parameters (gas prices, data payloads, etc.) systematically

4. **Collision Search**
   - Search for parameter combinations where:
     `keccak256(EIP191_PREFIX + keccak256(EIP712_PREFIX + domainSeparator + H(M))) = D`. 

A state-level actor could make such an attack feasible by leveraging several key factors. First, the search for matching hashes is highly parallelizable. Massive computing clusters can distribute the workload across thousands of nodes, reducing the effective search time significantly compared to a brute-force pre-image attack that would otherwise require approximately $2^{256}$ operations. The structural constraints of the problem—where only a small portion of the overall transaction data is variable—further decrease the search space.

In addition to computation, the availability of multiple valid targets simplifies the attacker’s challenge. Rather than having to force a collision on one uniquely specific transaction, any legitimate transaction that has met the threshold requirements and been signed can serve as a valid target. This multiplicity means the attacker need only find one collision from a pool of several candidates, each with only minor differences from one another.

Moreover, there is considerable flexibility in transaction parameters. The attacker can modify various components—such as gas parameters, data field contents, and the padding in the calldata—where even slight alterations can lead to completely different hash outputs. These opportunities for variability provide the attacker with extra degrees of freedom that can be used to steer the final hash toward a desired target. By analyzing a broad set of transactions, an attacker could also uncover and exploit recurring patterns in the resulting double-processed hashes, further optimizing their search.

#### Substantial Limits in Hash Input Entropy

Despite the fact that secure hash functions are designed with a number of security assurances intended to make finding collisions or inverting output functions practically impossible. However, these properties can be subverted in certain cases, such as in instances where the hash is iterating over a subset smaller than all of the potential outputs the hash function can generate.  

Entropy can have a substantial impact on the security assurances of modern hash functions. Cryptographic hash functions like keccak256 are designed to behave like random oracles—small changes in input (even a single bit) produce outputs that look uniformly random (the avalanche effect).  However, the actual randomness of the output depends on the entropy of the input:

- High-entropy inputs (e.g. truly random bytes) map to hash outputs that are uniformly distributed across the $2{256}$ possible values.
- Low-entropy inputs (e.g. only a few bits vary) can only occupy a correspondingly small subset of the output space, making collisions (two inputs hashing to the same value) far more likely within that subset.

 In specific, look at the `calldata` for these two different transactions. 

Here's the first one (the hack  TX `calldata`): 

```
0x6a76120200000000000000000000000096221423681a6d52e184d440a8efcebb105c7242000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000b2b2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be296951600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Here's a legitimate transaction on the same proxy for a call (using the same function; `execTransaction`) with the same nested `transferToken` call embedded within it. The biggest differences here are the recipient of the `execTransaction` struct, the token contract being invoked and the amount to be sent as well as the `nonce` / `_nonce`. 

```solidity 
0x6a761202000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f84c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000ee5b5b923ffce93a870b3104b7ca09c3db80047a00000000000000000000000000000000000000000000000000003691d6afc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Between these two transactions, there's 44 **total** bytes of variability. 439 out of 489 bytes between these transactions are identical. Beyond that, the vast majority of these bytes are identical (and repetitious); repeating zeroes. 

Both `calldata` strings present the following identical repetitious, low-entry strings:

1. Both `calldata` have identical function signatures to begin their strings. Following this calldata are 24 repeating zeroes. The `calldata` is the same for both. 
2. Following the first 32-byte string is another which contains an address in its upper-160 bits (20 bytes; hasn’t been left-padded yet). These 20 bytes are different between the two sets of `calldata`. However, they are both located in the same location. 
3. Afterward, there are 125 repeating zeroes consecutively in both sets of `calldata` up to the next element in the `calldata`. 
4. Following this, there is a `uint8` value in the code (represents a `nibble` potentially). This one byte in the hack transaction differs from what we see in legitimate transactions. 
5. Following this, there is another 60 bytes of nulls (zeroes) until the next data element is reached. This `data` element that gets reached is the `safeTxGas`. In the hack transaction, this value is `0xb2b2` and in the legitimate one its `0xf84c` (however, there are plenty of transactions where that value is `0xb2b1`, which would shrink the byte difference down to just a nibble or 1-byte versus 2 full bytes at this juncture). 
6. Following the `safeTxGas` value in the `calldata`, there are **317 consecutive identical null values** in the `calldata`. This repetition is only broken by a `0x1c` hexadecimal value (which is identical in both pieces of `calldata`. 
7. Following that `0x1c` value, we see `63` more identical zeroes in repetition. That is only broken by a 20-byte encoded address (which is different for both sets of `calldata`). Following that 20-byte address, there are another 20 identical repetitious zeroes which are interrupted by a 10-byte value, which is `0x3691d6afc0` in the legitimate transaction `calldata`, but all repetitious null bytes in the hack transaction. 
8. Moving past this 10-byte string, the final 182 bytes of the `calldata` (for both transactions) consists of repetitious identical zeroes. 

Between the two sets of `calldata` (between the legitimate and hack transaction), there are a total of 860 repetitious zeroes. That represents 430 out of the 484 total bytes of `calldata` (excluding the signatures which, of course, are not signed) across both transactions. All of those bytes (between the two) are identical in order and **identically placed** in the `calldata`. What I mean by that, while there may have been minor variations here and there with regards to the actual bytes in the `calldata`, the length of that variation was identical in both sets of `calldata`. 

For example, at the beginning of both transactions' `calldata`, the first 32 bytes are identical. However, the next 20-bytes differ. But that's only because the transactions are calling different 'token addresses' (i.e., `0x9622...` wasn't really a token address though). At the conclusion of that 20-byte string, both sets of `calldata` go back to mirroring one another. 

Its also worth considering the fact that there are likely 100+ different candidate transactions that are eligible to extract matching messages from (since domain separation is destroyed in this compromise due to the reasons we explored above). 

##### Effective Entropy Estimate

- Total `calldata` length ≈ `484` bytes (excluding signatures).
- Observed variability between hack and legitimate transactions ≈ `44` bytes.
- Remaining ~`440` bytes are identical and identically positioned zeroes or constants.
- Many fields are static or predictable (fixed gasToken, refundReceiver, operation, etc.).
- Nonce and some gas parameters provide limited variability.
- Address fields vary but are constrained to 20 bytes each, often from a limited set (e.g., known hot wallet addresses).

Overall, this suggests that the **effective entropy** (`k`) in the transaction hash input is roughly on the order of **44 bytes × 8 = 352 bits** max, but this is a **very loose upper bound** since some of those bytes encode structured data with limited variability (e.g., small integers, known addresses). Realistically, the **effective entropy is much lower**—likely between **32 to 64 bits**, as supported by prior analysis and the high similarity observed in hashes.

##### Consequence of Domain Separation Erosion

- The Gnosis Safe implementation nests `EIP-712` (typed, domain-separated) inside `EIP-191` (personal message) hashing for `v > 30` signatures.
- This effectively **breaks the domain separation** by allowing a signature to be validated against two distinct hash contexts.
- This doubles an attacker's “shot” at producing a collision: they can attempt to find a preimage that matches a hash under either scheme.
- This **raises practical collision chances** beyond the theoretical security bound of a single hash function collision.

**Multiple Candidate Targets and Search Space Reduction**

- There are 100+ legitimate candidate transactions the attacker could target.
- Each provides a unique **target hash `H(X)`** signed by authorized owners.
- The attacker’s task reduces to finding a malicious transaction `M` with hash `H'(M)` (under buggy verification) matching **any** of these `H(X)`.
- This multiplicity further **increases the attacker’s probability of success**, effectively multiplying the collision probability by ~100.

**Rough Probability Estimation**

- Assuming effective entropy `k ≈ 40` bits (a conservative estimate from variability and real-world constraints).
- Probability of random collision in one attempt: ~$1$ in $2^{40}$ (~1 in 1 trillion).
- With 100 target hashes, effective collision probability per attempt: ~$100/(2^{40})$ ≈ $1/(2^{33})$.
- With modern ASIC or FPGA farms capable of trillions of hashes per second, finding a collision in hours or days becomes **feasible**.
- The “double hashing” (`EIP-712` nested in `EIP-191`) **does not increase theoretical collision resistance**, but **creates practical avenues** to exploit inconsistencies and domain separation violations.

##### Final Assessment

- The **extensive repetition and low variability in transaction calldata drastically reduce the effective hash input entropy**.
- **Domain separation weakening due to nested hashing standards further undermines the security assumptions**, allowing multiple validation paths.
- **Multiple known signed target hashes multiply the feasible attack vectors**.

**Thus, the probability that an attacker capable of high-speed hashing could find a collision sufficient to exploit this vulnerability is non-negligible and practically plausible within reasonable timeframes given sufficient resources.** 

#### Non-Coincidental Similarities Between Hashes

1. On February 3rd, 2025, there were two transactions (legitimate) that were sent on the same block. Only one of those transactions executed successfully because they both had the same nonce (so the first one that was seen in the mempools or mined by miners in the block order got accepted). The signatures were the exact same. The unsuccessful transaction had a nonce value of `71` (in decimal) and the successful one had a nonce value of `70`. These nonce values are contract-specific (to the Gnosis Safe specification) and do not correlate with the nonce of the `tx.origin` (from the scope of miners looking to validate the order of transactions). 
2. The signature(s) for these transcations (multi-signature; 3 were submitted; all EOA signatures) each had a value above 30 (`v > 30`). Thus, the signature verification process was releagted to the `0x1945...` workflow specified by `EIP-191`. This, of course, leads to the "double hashing" phenomenon that we observed prior in this conversation. 
3. For the transaction that went through, the `dataHash	` that the signatures were **verified against** was (`0x0f9ec218c2852a784e9ca66849254e88e43925fb1fd1aa81aff29150ba40d82e`). However, the **actual** `dataHash` **for that transaction was** `0x2802c80b37293b9b57eb02deb85196103b6b74f0220b0928bb1c1c96f59e04f8`. We're not going to pay attention to the failed transaction at this point in time (since the hash that was produced was rendered invalid). Notably, the **very next** `execTransaction` function that was executed on the chain was by the hacker on February 21st, 2025. The hash that the hack transaction was verified against was `0x28eddb7e7d1dca66673b339ca554c63603dede0512d6da0300cf782f68a8a260`. However, the `dataHash` for the hack transaction was `0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8` (which is not what the signatures were verified against for the hack transaction). 
4. Summing up what we observed in points 1 through 3, neither the successful (legitimate) transaction on February 3rd, 2025 nor the hack transaction (on February 21st, 2025), had their signatures validated against the correct hash (we've already uncovered this bug/flaw in the Gnosis Safe 1.1.1 contracts). However, the **correct** `dataHash` for the legitimate transaction and the double-processed hash for the hack transaction appear to be **very similar in nature**. When considering the fact that both of these values should be `keccak256` hash outputs, the algorithmically derived similarity scores between the two strings **must be taken into account**. 

#### String Similarity Comparison

Following what was stated in #4, it should be noted that the legitimate transaction had a `dataHash` value of `0x2802c80b37293b9b57eb02deb85196103b6b74f0220b0928bb1c1c96f59e04f8`. The hack transaction's `dataHash` was `0xb3476d061aeb8fc1d605a873c483a2402d88a68a9cdd1a8b47655dd55ba004f8`; however, its signatures were verified against the hash `0x28eddb7e7d1dca66673b339ca554c63603dede0512d6da0300cf782f68a8a260`. We're going to compare the latter value from the hack transaction with the `dataHash` from the legitimate transaction. 

Our comparison involves using the following algorithmic string comparison metrics: 'Levenshtein', 'NeedlemanWunch', 'Smith-Waterman', 'Smith-Waterman Gotoh', 'Smith-Waterman Gotoh Windowed Affine', 'Jaro', 'Jaro Winkler' and the 'Qgrams Distance'. 

Below are brief summaries of each string similarity index scoring's methodology: 

1. **Levenshtein**: Measures the minimum number of single-character edits (insertions, deletions, substitutions) required to transform one string into another.
2. **Needleman-Wunsch**: A global alignment algorithm that computes the optimal full-sequence alignment between two strings using dynamic programming, applying configurable scores for matches, mismatches, and gap penalties.
3. **Smith-Waterman**: A local alignment algorithm that identifies the highest-scoring matching subsequences between two strings, using dynamic programming and truncating negative scores to zero to isolate local regions of similarity.
4. **Smith-Waterman Gotoh**: An enhancement of Smith-Waterman that introduces affine gap penalties, distinguishing between the cost of opening a gap and extending it, resulting in more biologically or linguistically realistic alignments.
5. **Smith-Waterman Gotoh Windowed Affine**: A variant of Gotoh’s algorithm that applies a sliding window to limit the alignment search space, improving efficiency while preserving affine gap scoring for local similarity detection.
6. **Jaro**: A string similarity metric that accounts for the number and order of matching characters, as well as the number of transpositions, emphasizing both character proximity and relative positioning.
7. **Jaro-Winkler**: An extension of the Jaro metric that boosts similarity scores for strings with common prefixes, making it particularly effective for short strings like personal names or identifiers.
8. **Qgrams Distance**: A token-based distance metric that fragments strings into overlapping substrings of length q and computes similarity based on the count of shared vs. non-shared q-grams, capturing typographic and structural variations.

The scores that we received for the two aforementioned hashes (`0x28eddb7e7d1dca66673b339ca554c63603dede0512d6da0300cf782f68a8a260` and `0x2802c80b37293b9b57eb02deb85196103b6b74f0220b0928bb1c1c96f59e04f8`) were as follows: 

| Algorithm                                | Score | Percentile Rank | Type           | Range            | Interpretation                                               |
| ---------------------------------------- | ----- | --------------- | -------------- | ---------------- | ------------------------------------------------------------ |
| **Levenshtein**                          | 14    | 62.50%          | Distance       | [0, ∞)           | Low dissimilarity – only 14 edits needed. Lower is better. Suggests high similarity. |
| **Needleman-Wunsch**                     | 55    | 75.00%          | Similarity     | Unbounded (±)    | Moderate to strong global similarity. A higher score reflects overall string alignment. |
| **Smith-Waterman**                       | 4     | 37.50%          | Similarity     | ≥ 0              | Very weak local similarity. Likely matches only a very small substring or poorly aligned. |
| **Smith-Waterman Gotoh**                 | 4     | 37.50%          | Similarity     | ≥ 0              | Same as Smith-Waterman – minimal local alignment match with affine gap penalties. |
| **Smith-Waterman Gotoh Windowed Affine** | 4     | 37.50%          | Similarity     | ≥ 0              | Same minimal alignment observed; likely a short or poor local match. |
| **Jaro**                                 | 61    | 87.50%          | Similarity (%) | [0.0, 1.0] × 100 | Moderate similarity – Jaro score of 0.61 suggests over half of the characters align well. |
| **Jaro-Winkler**                         | 69    | 100.00%         | Similarity (%) | [0.0, 1.0] × 100 | Stronger similarity with a matching prefix – good for name or identifier comparison. |
| **QGrams Distance**                      | 3     | 12.50%          | Distance       | [0, max_qgrams]  | Very low dissimilarity – indicates strong structural overlap between strings. |
0
#### Attack Vector: Chosen Prefix Second Pre-Image Attacks

Speaking practically, hash collisions should be **100% impossible to find** assuming a robust hash function is in use (i.e., `keccak256`). 

There are a # of transactions (using execTransaction) where the only tangible change would be the nonce. Another key detail worth noting is the fact that the execTransaction attempt (before the hack transaction) that was made ended up failing on the actual blockchain. So the nonce value that **was** going to be used for that transaction was able to be replayed. Of course, those two other minor details that I mentioned were the only things that were materially different in this transaction versus legitimate ones (i.e., the supposed recipient of the malicious transfer & the to address for the execTransaction function at a higher level). 

**Impact on ‘Search Space’** 

When almost every field in the transaction is fixed—with only a handful of bytes (say, 2–4 bytes for the nonce and possibly a couple bytes for the malicious “to” addresses) actually varying—the effective space of legitimate transaction hashes is dramatically reduced compared to the full 256-bit hash space.

**Breaking Down the Math**

>    In an ideal case where every bit of the 32‑byte (256‐bit) output can vary randomly, you’re looking at $2^{256}$ possible hash outcomes. However, in the practical scenario you’re describing, nearly every component of the transaction (such as the signature data, gas parameters, and many other fields) has been used repeatedly. In many such execTransaction calls, the only changing element is the nonce—and in some cases, even that may only be a few bytes in practice (for example, if the nonce is incremented from a small number).

-   For example, if the only “free” or variable part is a 4‑byte nonce, then the possible number of different inputs that the owners have signed is about $2^{(4×8)}$ = $2^{32}$ (roughly 4.3 billion) different messages. Compare this with the $2^{256}$ possibilities in the full hash space. In effect, the legitimate transaction hash “lives” in a subspace whose size is $2^{32}$, not $2^{256}$.
-   More generally, if only N bytes are allowed to vary, the effective number of possibilities is approximately $2^{(8N)}$. For $N=4$, that’s $2^{32}$; for $N=8$, that’s $2^{64}$.
    -   The reduction factor in difficulty is roughly $2^{(256 – 8N)}$ for $N = 4$.
    -   Reduction factor ≈ $2^{(256 – 32)}$ = $2^{224}$ ; assuming $N = 8$
    -   Reduction factor (another example) ≈ $2^{(256 – 64)}$ = $2^{192}$

In practical terms, a reduction by a factor of $2^{224}$ (approximately $2.7$×$10^{67}$) or $2^{192}$ (approximately $6.3×10^{57}$) means the attacker’s brute-force search isn’t facing a full $2^{256}$ space; it’s facing a space that’s many orders of magnitude smaller.

If, aside from two minor differences (*the malicious recipient and the overall* `execTransaction` “to” address), all other transaction parameters—including the nonce used in the signed data—come from a very narrowly defined set of values (perhaps differing only by a few bytes), then the legitimate message hashes are drawn from this **minimal subspace**. That makes it exponentially easier for an attacker with unlimited candidate-generation capability to “mine” variations in order to match one of the valid signed hashes.

For example, if the effective variable region is only 4 bytes, then instead of a $1$ in $2^{256}$ chance, each candidate malicious transaction might have a $1$ in $2^{32}$ chance of matching one of the limited set of legitimate hashes. Granted, $2^{32}$ is still a large number in isolation, but when compared to $2^{256}$, it’s an astronomical reduction in the work factor—by roughly $2^{224}$ times.

#### Concluding Statements

When nearly every part of the transaction is fixed and only a few bytes (*such as 2–4 bytes for the nonce or minor differences in addresses*) are variable, the effective search space for legitimate signed hashes shrinks drastically—perhaps to somewhere between $2^{32}$ and $2^{64}$ possible values instead of $2^{256}$. This reduction (*by a factor of* $2^{(256 – 8N)})$ can make brute-force matching of a legitimate hash orders of magnitude easier compared to an unconstrained scenario, even though in absolute terms the space might still be large. In practical terms, with a very limited subspace of valid transactions, an attacker with unlimited candidate tweaks has a far better chance of “mining” a malicious transaction that matches the valid signed data.

##### Breaking Down Entropy and the Birthday Paradox

>    Hash functions are designed so that—in theory—they have a huge output space (for instance, keccak256 produces a 256‐bit value, which means $2^{256}$ possible outputs). However, when the input data has low “entropy” (that is, only a small number of bytes truly vary), the actual number of distinct inputs is dramatically lower. 

**Quick Example to Help Anyone Understand That May Be Confused**

Imagine you supply 64 bytes to a hash function. If every one of those 64 bytes can be any value, then there are $2^{(64×8)}$ = $2^{512}$ possible different inputs. Of course, no modern hash function even aims to be collision-free over such an enormous space; what matters is that a cryptographic hash function should make it infeasible to find two different inputs that produce the same output.

Now suppose that although you supply 64 bytes, only 8 of those bytes actually vary—the remaining 56 bytes are fixed. This means the effective input variability is only 8 bytes, or 64 bits, giving only $2^{64}$ distinct inputs. Even though the hash function still produces a 256-bit output, it will only ever actually produce at most $2^{64}$ distinct hash values (assuming the hash behaves like a random oracle). That is a dramatically smaller subspace compared to $2^{256}$.

**Birthday Paradox Relevant with Severely Constrained Search**

The classic birthday paradox tells us that if you are sampling uniformly from N possible outcomes, you only need roughly √N samples to have a significant chance of finding a collision.

-   In a full 256-bit setting, $√(2^{256})$ is about $2^{128}$—a number that is astronomically high and practically out of reach.
-   However, if the attacker’s effective input space is only $2^{64}$, the square root is $2^{32}$, which is many orders of magnitude smaller. Thus, once you have on the order of $2^{32}$ distinct inputs (hashes), there’s a roughly 50% chance of a collision in that restricted set.

**How this Makes Attacks More Feasible**

1.   If legitimate transactions are only drawn from that small subspace (say, because only 8 bytes vary among 64-byte inputs), an attacker trying to find a hash that matches one of these transactions only has to search through $2^{64}$ possibilities instead of $2^{256}$. That is a massive reduction in the difficulty.
2.   Even though $2^{64}$ is still a large number (approximately $1.8×10^{19}$ possibilities), it is entirely within the realm of possibility if the attacker is able to try a large number of variations rapidly, especially when considering that many legitimate transactions may differ only by a few bytes like a small nonce. This makes the effective collision probability (*or the ability to* “**mine**” *a valid hash*) orders of magnitude better than in a full 256-bit scenario.

### Appendix (Additional Proof)

I figured that I would submit an ‘additional proof’ for this section of the report since everything that we’ve explored has been in the EVM thus far. Let’s go ahead and look at one of the better visual explorers out there called ‘Tenderly’. 

If we visit the hack transaction on Tenderly, we can view it from all sorts of different angles (i.e., full stack execution trace, debugging it step by step in their EVM. 
