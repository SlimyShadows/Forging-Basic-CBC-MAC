import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CBCMACTest {

    private static class TestCase {
        final int l;
        final byte[] tag;

        TestCase(int l, String tagHex) {
            this.l = l;
            this.tag = CBCMAC.hexToBytes(tagHex);
        }
    }

    public static void runTests() throws Exception {
        System.out.println("--- Running Automated CBC-MAC Tests (Problem 3a) ---");

        byte[] key = CBCMAC.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        String msgHex = "6bc1bee22e409f96e93d7e117393172a "
                      + "ae2d8a571e03ac9c9eb76fac45af8e51 "
                      + "30c81c46a35ce411e5fbc1191a0a52ef "
                      + "f69f2445df4f9b17ad2b417be66c3710";
        byte[] fullMsg = CBCMAC.hexToBytes(msgHex);

        TestCase[] table1 = {
            new TestCase(1, "3ad77bb40d7a3660a89ecaf32466ef97"),
            new TestCase(2, "b148c17f309ee692287ae57cf12add49"),
            new TestCase(3, "c93d11bfaf08c5dc4d90b37b4dee002b"),
            new TestCase(4, "a7356e1207bb406639e5e5ceb9a9ed93")
        };

        // 1. Known-answer tests from Table 1
        for (TestCase tc : table1) {
            byte[] m = Arrays.copyOfRange(fullMsg, 0, tc.l * 16);
            byte[] computedTag = CBCMAC.mac(key, m);
            if (!Arrays.equals(computedTag, tc.tag)) {
                throw new AssertionError("MAC mismatch for l=" + tc.l);
            }
            if (!CBCMAC.verify(key, m, tc.tag)) {
                throw new AssertionError("Verify failed to accept valid pair for l=" + tc.l);
            }
        }
        System.out.println("[PASS] Table 1 known-answer tests for l = 1, 2, 3, 4.");

        // 2. Empty message and 17-byte message checks
        try {
            CBCMAC.mac(key, new byte[0]);
            throw new AssertionError("mac() should throw on empty message");
        } catch (IllegalArgumentException expected) {
            // Expected
        }
        if (CBCMAC.verify(key, new byte[0], new byte[16])) {
            throw new AssertionError("verify() should return false on empty message");
        }

        try {
            CBCMAC.mac(key, new byte[17]);
            throw new AssertionError("mac() should throw on 17-byte message");
        } catch (IllegalArgumentException expected) {
            // Expected
        }
        if (CBCMAC.verify(key, new byte[17], new byte[16])) {
            throw new AssertionError("verify() should return false on 17-byte message");
        }
        System.out.println("[PASS] Empty message and 17-byte message error/rejection checks.");

        // 3. Invalid tag lengths: 0, 15, and 17 bytes
        byte[] validM = Arrays.copyOfRange(fullMsg, 0, 16);
        if (CBCMAC.verify(key, validM, new byte[0])) {
            throw new AssertionError("verify() should return false for 0-byte tag");
        }
        if (CBCMAC.verify(key, validM, new byte[15])) {
            throw new AssertionError("verify() should return false for 15-byte tag");
        }
        if (CBCMAC.verify(key, validM, new byte[17])) {
            throw new AssertionError("verify() should return false for 17-byte tag");
        }
        System.out.println("[PASS] Invalid tag length checks (0, 15, 17 bytes).");

        // 4. Single-bit flips across message and tag for each pair in Table 1
        for (TestCase tc : table1) {
            byte[] m = Arrays.copyOfRange(fullMsg, 0, tc.l * 16);

            // Flip every single bit in the message one at a time
            for (int byteIdx = 0; byteIdx < m.length; byteIdx++) {
                for (int bitIdx = 0; bitIdx < 8; bitIdx++) {
                    byte[] badM = Arrays.copyOf(m, m.length);
                    badM[byteIdx] ^= (byte) (1 << bitIdx);
                    if (CBCMAC.verify(key, badM, tc.tag)) {
                        throw new AssertionError(
                                "verify() accepted modified message for l=" + tc.l
                                        + " at byte " + byteIdx + ", bit " + bitIdx);
                    }
                }
            }

            // Flip every single bit in the tag one at a time
            for (int byteIdx = 0; byteIdx < tc.tag.length; byteIdx++) {
                for (int bitIdx = 0; bitIdx < 8; bitIdx++) {
                    byte[] badTag = Arrays.copyOf(tc.tag, tc.tag.length);
                    badTag[byteIdx] ^= (byte) (1 << bitIdx);
                    if (CBCMAC.verify(key, m, badTag)) {
                        throw new AssertionError(
                                "verify() accepted modified tag for l=" + tc.l
                                        + " at byte " + byteIdx + ", bit " + bitIdx);
                    }
                }
            }
        }
        System.out.println("[PASS] Single-bit flip tests on messages and tags for all Table 1 pairs.");

        // 5. Automated sanity check for Problem 3(b) and 3(c)
        byte[] target = "from=alice&to=mallory&amount=1000000&note=rent!!".getBytes(StandardCharsets.UTF_8);
        CBCMAC.Oracle oracle = new CBCMAC.Oracle(null);
        byte[] forgedTag = CBCMAC.forge(oracle::query, target);
        if (oracle.queries.size() != 2) {
            throw new AssertionError("Expected exactly 2 oracle queries, got " + oracle.queries.size());
        }
        if (oracle.queries.contains(CBCMAC.bytesToHex(target))) {
            throw new AssertionError("Oracle should never receive the target message directly");
        }
        if (!oracle.verifyTarget(target, forgedTag)) {
            throw new AssertionError("Forged tag failed verification");
        }

        CBCMAC.Oracle fixedOracle = new CBCMAC.Oracle(3);
        try {
            CBCMAC.forge(fixedOracle::query, target);
            throw new AssertionError("Fixed-length 3-block oracle should reject 2-block first query");
        } catch (IllegalArgumentException expected) {
            // Expected
        }
        System.out.println("[PASS] Forgery and fixed-length oracle unit checks.");
        System.out.println("All automated tests passed successfully!");
    }

    public static void main(String[] args) {
        try {
            runTests();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}