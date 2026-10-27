# Assignment 4: Forging Basic CBC-MAC
**Name:** Dante Ruzic

---

## Problem 1: Basic CBC-MAC

### a. Definitions of $\mathsf{Gen}$, $\mathsf{Mac}$, and $\mathsf{Vrfy}$

Let $F$ be AES-128, where keys, blocks, and tags are 16 bytes (128 bits), i.e., $\{0,1\}^{128}$.

* **$\mathsf{Gen}()$:** Samples and outputs a uniformly random 128-bit secret key $k \leftarrow \{0, 1\}^{128}$.
* **$\mathsf{Mac}_k(m)$:** Given a key $k \in \{0,1\}^{128}$ and a message $m = m_1 \,\Vert{}\, m_2 \,\Vert{}\, \cdots \,\Vert{}\, m_\ell$ consisting of $\ell \ge 1$ blocks with each $m_i \in \{0,1\}^{128}$:
  1. Define the initial chaining value as the 128-bit all-zero block:
     $$x_0 = 0^{128}$$
  2. For $i = 1, 2, \ldots, \ell$, recursively define the $i$-th chaining value by XORing the previous chaining value $x_{i-1}$ with block $m_i$ and encrypting under $F_k$:
     $$x_i = F_k(x_{i-1} \oplus m_i)$$
  3. Output the final chaining value as the tag:
     $$t = x_\ell$$
* **$\mathsf{Vrfy}_k(m, t)$:** Given key $k$, message $m$, and candidate tag $t$:
  1. If $m$ is empty, $\vert{}m\vert{}$ is not a multiple of 128 bits (16 bytes), or $\vert{}t\vert{} \neq 128$ bits (16 bytes), output $0$ (reject).
  2. Otherwise, compute 
  $\~(\.tilde broke here.){t} = \mathsf{Mac}_k(m)$ and compare $\~(\.tilde broke here.){t}$ with $t$ in constant time. Output $1$ (accept) if $\~{t} = t$, and $0$ (reject) otherwise.

### b. Two Differences Between CBC-MAC and CBC-Mode Encryption

1. **Initialization Vector (IV):** Basic CBC-MAC fixes the initial chaining value to $x_0 = 0^{128}$ (deterministic). In contrast, CPA-secure CBC-mode encryption must sample a fresh, unpredictable, uniformly random IV $x_0 \leftarrow \{0,1\}^{128}$ for every encryption (using a fixed IV in CBC encryption leaks whether two messages share a common prefix, whereas using a random IV in CBC-MAC allows trivial 1-block forgeries).
2. **Output Values:** Basic CBC-MAC discards all intermediate chaining values $x_1, \ldots, x_{\ell-1}$ and outputs only the final block $t = x_\ell$ (throwing away information so only a 16-byte integrity tag is sent). CBC-mode encryption outputs the IV along with every intermediate block $(x_0, x_1, \ldots, x_\ell)$ as the ciphertext so that the receiver can invert each block and recover the full plaintext.

### c. Condition on Message Lengths for Security

When $F$ is a secure pseudorandom function (PRF), basic CBC-MAC is secure **if and only if all messages authenticated and verified under a given key $k$ are restricted to a single fixed block length $\ell \ge 1$ chosen in advance** (i.e., the message space is $\{0,1\}^{128\ell}$ for a fixed $\ell$, or more generally a prefix-free message space). If messages of varying lengths are permitted under the same key, an attacker can splice tags across messages of different lengths to forge valid tags.

---

## Problem 2: A Forgery on Messages of Different Lengths

### a. Chain Values of the Forged Message $m^*$

Let $m = m_1 \,\Vert{}\, \cdots \,\Vert{}\, m_\ell$ ($\ell \ge 1$) have chain values $x_0, x_1, \ldots, x_\ell$ with tag $t = x_\ell = \mathsf{Mac}_k(m)$, and let $m' = m'_1 \,\Vert{}\, \cdots \,\Vert{}\, m'_{\ell'}$ ($\ell' \ge 1$) have chain values $x'_0, x'_1, \ldots, x'_{\ell'}$ with tag $t' = x'_{\ell'} = \mathsf{Mac}_k(m')$.

The forged message has $\ell + \ell'$ blocks and is defined as:
$$m^* = m_1 \,\Vert{}\, \cdots \,\Vert{}\, m_\ell \,\Vert{}\, (m'_1 \oplus t) \,\Vert{}\, m'_2 \,\Vert{}\, \cdots \,\Vert{}\, m'_{\ell'}$$
Let $m^*_i$ denote the $i$-th block of $m^*$ and $x^*_i$ denote its $i$-th chaining value for $0 \le i \le \ell + \ell'$:

1. **Initial value ($i = 0$):** By definition of $\mathsf{Mac}_k$,
   $$x^*_0 = 0^{128} = x_0$$
2. **First $\ell$ blocks ($1 \le i \le \ell$):** Since $m^*_i = m_i$ for all $1 \le i \le \ell$ and $x^*_0 = x_0$, induction on $i$ yields:
   $$x^*_i = F_k(x^*_{i-1} \oplus m^*_i) = F_k(x_{i-1} \oplus m_i) = x_i \quad \text{for } 1 \le i \le \ell$$
   In particular, after block $\ell$:
   $$x^*_\ell = x_\ell = t$$
3. **Block $\ell + 1$:** The $(\ell+1)$-st block of $m^*$ is $m^*_{\ell+1} = m'_1 \oplus t$. Substituting $x^*_\ell = t$ gives:
   $$x^*_{\ell+1} = F_k\big(x^*_\ell \oplus (m'_1 \oplus t)\big) = F_k\big(t \oplus m'_1 \oplus t\big) = F_k(m'_1) = F_k(0^{128} \oplus m'_1) = F_k(x'_0 \oplus m'_1) = x'_1$$
4. **Remaining blocks ($\ell + 2 \le \ell + j \le \ell + \ell'$ when $\ell' \ge 2$):** For $j = 2, \ldots, \ell'$, the $(\ell+j)$-th block of $m^*$ is $m^*_{\ell+j} = m'_j$. Since $x^*_{\ell+1} = x'_1$, induction on $j$ yields:
   $$x^*_{\ell+j} = F_k(x^*_{\ell+j-1} \oplus m'_j) = F_k(x'_{j-1} \oplus m'_j) = x'_j \quad \text{for } 2 \le j \le \ell'$$
5. **Final tag:** Evaluating at $j = \ell'$ gives the final chaining value of $m^*$:
   $$\mathsf{Mac}_k(m^*) = x^*_{\ell + \ell'} = x'_{\ell'} = t'$$

**Why $m^*$ differs from both queried messages:**
Every valid message contains at least one block, so $\ell \ge 1$ and $\ell' \ge 1$. The block length of $m^*$ is $\ell + \ell'$.
* Since $\ell' \ge 1$, we have $\ell + \ell' > \ell$, so $m^*$ is strictly longer than $m$ and thus $m^* \neq m$.
* Since $\ell \ge 1$, we have $\ell + \ell' > \ell'$, so $m^*$ is strictly longer than $m'$ and thus $m^* \neq m'$.

### b. Forging a Valid Tag on Target $M$ with Two Queries

Let the target message be $M = M_1 \,\Vert{}\, M_2 \,\Vert{}\, \cdots \,\Vert{}\, M_L$ with $L \ge 2$ blocks. We instantiate part (a) with $\ell = L - 1 \ge 1$ and $\ell' = 1$:

1. **Query 1:** Query the MAC oracle on the first $L - 1$ blocks of $M$:
   $$m = M_1 \,\Vert{}\, M_2 \,\Vert{}\, \cdots \,\Vert{}\, M_{L-1}$$
   Let $t = \mathsf{Mac}_k(m)$ be the returned 16-byte tag.
2. **Query 2:** Query the MAC oracle on the single 16-byte block formed by XORing the last block $M_L$ with $t$:
   $$m' = M_L \oplus t$$
   Let $t' = \mathsf{Mac}_k(m')$ be the returned 16-byte tag.
3. **Output Forged Tag:** Output $t'$ as the tag for $M$.

**Correctness:** By part (a) with $\ell = L - 1$ and $\ell' = 1$, $t'$ is the valid tag for:
$$m^* = m_1 \,\Vert{}\, \cdots \,\Vert{}\, m_{L-1} \,\Vert{}\, (m'_1 \oplus t) = M_1 \,\Vert{}\, \cdots \,\Vert{}\, M_{L-1} \,\Vert{}\, ((M_L \oplus t) \oplus t) = M_1 \,\Vert{}\, \cdots \,\Vert{}\, M_{L-1} \,\Vert{}\, M_L = M$$
Hence $\mathsf{Mac}_k(M) = t'$ and $\mathsf{Vrfy}_k(M, t') = 1$.

**Why neither query equals $M$:**
* Query 1 ($m$) has $L - 1$ blocks, whereas $M$ has $L$ blocks ($L - 1 < L$), so $m \neq M$.
* Query 2 ($m'$) has $1$ block, whereas $M$ has $L \ge 2$ blocks ($1 < 2 \le L$), so $m' \neq M$.

**Success Probability:**
Because the chaining value cancellation $(M_L \oplus t) \oplus t = M_L$ holds deterministically for every key $k \in \{0,1\}^{128}$, the success probability is **1** (100%).

### c. Why the Attacks Fail Under a Fixed-Length Check ($\ell$ Blocks Only)

Suppose $\mathsf{Mac}_k$ and $\mathsf{Vrfy}_k$ reject any message whose length is not exactly $\ell$ blocks (for a fixed $\ell \ge 1$):

* **Failure of Part (a):** For the MAC oracle to accept the two queries $m$ and $m'$, both must have length $\ell$ blocks ($\ell \ge 1$). However, the spliced message $m^*$ then has length $\ell + \ell = 2\ell$ blocks. Since $2\ell > \ell$ for all $\ell \ge 1$, $\mathsf{Vrfy}_k(m^*, t')$ immediately rejects $m^*$ because its length is not $\ell$ blocks. (Conversely, if the attacker chooses lengths $\ell_1 + \ell_2 = \ell$ with $\ell_1, \ell_2 \ge 1$, the oracle rejects both queries since $\ell_1 < \ell$ and $\ell_2 < \ell$.)
* **Failure of Part (b):** For the target $M$ to be accepted by $\mathsf{Vrfy}_k$, $M$ must have length $L = \ell$ blocks. The attack in part (b) queries $m$ of length $L - 1 = \ell - 1$ blocks and $m'$ of length $1$ block. Since $\ell - 1 \neq \ell$, the MAC oracle rejects Query 1 immediately (and when $\ell \neq 1$, it also rejects the 1-block Query 2).

---

## Problem 3: Demo Outputs (3b and 3c)

### Output from Problem 3(b) and 3(c) (`make demo`)

*(Note: Because the oracle samples a fresh random AES-128 key on each run, `Tag 1`, `Query 2`, `Tag 2`, and `Forged Tag` change on every run, while `Target` and `Query 1` remain fixed, and `Tag 2` always equals `Forged Tag`.)*

```text
--- Problem 3(b): Variable-Length Forgery Demo ---
Target ASCII : from=alice&to=mallory&amount=1000000&note=rent!!
Target (hex) : 66726f6d3d616c69636526746f3d6d616c6c6f727926616d6f756e743d31303030303030266e6f74653d72656e742121
Query 1 (hex): 66726f6d3d616c69636526746f3d6d616c6c6f727926616d6f756e743d313030
Tag 1   (hex): d1ed11a3e3f0fe2b4065870f8f960316
Query 2 (hex): e1dd2193c59e915f2558f56ae1e22237
Tag 2   (hex): 22cce51044e8837137d1954a49c59140
Forged Tag (hex)               : 22cce51044e8837137d1954a49c59140
Did oracle ever receive target?: false
Verify(target, forgedTag)      : true
Successful forgeries over 100 trials: 100/100

--- Problem 3(c): Fixed-Length Check (3-Block Restriction) ---
Part 2(b) attack failed at Query 1: Oracle restricts queries to exactly 3 blocks (48 bytes), but received 2 blocks (32 bytes).
Part 2(a) two-3-block-query splicing (6-block m*) accepted by verifier?: false
```
