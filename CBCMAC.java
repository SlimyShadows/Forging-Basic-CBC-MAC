import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class CBCMAC {

    public static byte[] xorBlocks(byte[] b1, byte[] b2) {
        if (b1 == null || b2 == null || b1.length != b2.length) {
            throw new IllegalArgumentException("Blocks must be non-null and of equal length.");
        }
        byte[] result = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            result[i] = (byte) (b1[i] ^ b2[i]);
        }
        return result;
    }

    public static byte[] mac(byte[] key, byte[] msg) throws Exception {
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("Key length must be exactly 16 bytes (128 bits).");
        }
        if (msg == null || msg.length == 0 || msg.length % 16 != 0) {
            throw new IllegalArgumentException("Message length must be a positive multiple of 16 bytes.");
        }

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] chainVal = new byte[16]; // x_0 = 0^128

        for (int i = 0; i < msg.length; i += 16) {
            byte[] block = Arrays.copyOfRange(msg, i, i + 16);
            chainVal = cipher.doFinal(xorBlocks(chainVal, block));
        }

        return chainVal;
    }

    public static boolean verify(byte[] key, byte[] msg, byte[] tag) {
        if (key == null || key.length != 16
                || msg == null || msg.length == 0 || msg.length % 16 != 0
                || tag == null || tag.length != 16) {
            return false;
        }
        try {
            byte[] expectedTag = mac(key, msg);
            return MessageDigest.isEqual(expectedTag, tag);
        } catch (Exception e) {
            return false;
        }
    }

    public static byte[] hexToBytes(String s) {
        s = s.replaceAll("\\s+", "");
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even number of characters.");
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException("Invalid hex character in input.");
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static class Oracle {
        private final byte[] key;
        public final Set<String> queries;
        private final Integer enforceLength;

        public Oracle(Integer enforceLength) throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, new SecureRandom());
            this.key = keyGen.generateKey().getEncoded();
            this.queries = new HashSet<>();
            this.enforceLength = enforceLength;
        }

        public byte[] query(byte[] msg) throws Exception {
            if (msg == null || msg.length == 0 || msg.length % 16 != 0) {
                throw new IllegalArgumentException("Message length must be a positive multiple of 16 bytes.");
            }
            if (enforceLength != null && msg.length != enforceLength * 16) {
                throw new IllegalArgumentException(
                        "Oracle restricts queries to exactly " + enforceLength + " blocks ("
                                + (enforceLength * 16) + " bytes), but received "
                                + (msg.length / 16) + " blocks (" + msg.length + " bytes).");
            }
            queries.add(bytesToHex(msg));
            return mac(key, msg);
        }

        public boolean verifyTarget(byte[] msg, byte[] tag) {
            if (msg == null || msg.length == 0 || msg.length % 16 != 0) {
                return false;
            }
            if (enforceLength != null && msg.length != enforceLength * 16) {
                return false;
            }
            return verify(key, msg, tag);
        }
    }

    @FunctionalInterface
    public interface QueryFunction {
        byte[] apply(byte[] msg) throws Exception;
    }

    public static byte[] forge(QueryFunction queryFunc, byte[] target) throws Exception {
        if (target == null || target.length < 32 || target.length % 16 != 0) {
            throw new IllegalArgumentException("Target message must consist of at least 2 blocks (32+ bytes).");
        }

        // Query 1: First L - 1 blocks of target
        byte[] m = Arrays.copyOfRange(target, 0, target.length - 16);
        byte[] t = queryFunc.apply(m);

        // Query 2: single block m' = M_L XOR t
        byte[] mL = Arrays.copyOfRange(target, target.length - 16, target.length);
        byte[] mPrime = xorBlocks(mL, t);
        byte[] tPrime = queryFunc.apply(mPrime);

        return tPrime;
    }

    public static void runDemo() throws Exception {
        System.out.println("--- Problem 3(b): Variable-Length Forgery Demo ---");
        byte[] target = "from=alice&to=mallory&amount=1000000&note=rent!!".getBytes(StandardCharsets.UTF_8);

        Oracle oracle = new Oracle(null);
        System.out.println("Target ASCII : from=alice&to=mallory&amount=1000000&note=rent!!");
        System.out.println("Target (hex) : " + bytesToHex(target));

        final int[] queryNum = {0};
        byte[] forgedTag = forge(msg -> {
            queryNum[0]++;
            byte[] tag = oracle.query(msg);
            System.out.println("Query " + queryNum[0] + " (hex): " + bytesToHex(msg));
            System.out.println("Tag " + queryNum[0] + "   (hex): " + bytesToHex(tag));
            return tag;
        }, target);

        boolean targetQueried = oracle.queries.contains(bytesToHex(target));
        boolean valid = oracle.verifyTarget(target, forgedTag);

        System.out.println("Forged Tag (hex)               : " + bytesToHex(forgedTag));
        System.out.println("Did oracle ever receive target?: " + targetQueried);
        System.out.println("Verify(target, forgedTag)      : " + valid);

        int successCount = 0;
        for (int i = 0; i < 100; i++) {
            Oracle trialOracle = new Oracle(null);
            byte[] ft = forge(trialOracle::query, target);
            if (trialOracle.verifyTarget(target, ft)
                    && !trialOracle.queries.contains(bytesToHex(target))) {
                successCount++;
            }
        }
        System.out.println("Successful forgeries over 100 trials: " + successCount + "/100");
    }

    public static void runFixedLengthDemo() throws Exception {
        System.out.println("\n--- Problem 3(c): Fixed-Length Check (3-Block Restriction) ---");
        byte[] target = "from=alice&to=mallory&amount=1000000&note=rent!!".getBytes(StandardCharsets.UTF_8);
        Oracle oracleFixed = new Oracle(3);

        // 1. Repeat the Problem 2(b) / 3(b) attack against the 3-block oracle
        try {
            forge(oracleFixed::query, target);
        } catch (IllegalArgumentException e) {
            System.out.println("Part 2(b) attack failed at Query 1: " + e.getMessage());
        }

        // 2. Also show what happens if the attacker makes two valid 3-block queries as in Problem 2(a)
        byte[] m = target; // 3 blocks
        byte[] mPrime = target; // 3 blocks
        byte[] t = oracleFixed.query(m);
        byte[] tPrime = oracleFixed.query(mPrime);

        byte[] forged6Block = new byte[96];
        System.arraycopy(m, 0, forged6Block, 0, 48);
        byte[] mPrime1XorT = xorBlocks(Arrays.copyOfRange(mPrime, 0, 16), t);
        System.arraycopy(mPrime1XorT, 0, forged6Block, 48, 16);
        System.arraycopy(mPrime, 16, forged6Block, 64, 32);

        boolean verify6Block = oracleFixed.verifyTarget(forged6Block, tPrime);
        System.out.println("Part 2(a) two-3-block-query splicing (6-block m*) accepted by verifier?: " + verify6Block);
    }

    public static void main(String[] args) 
    {
        try {
            if (args.length == 0) 
            {
                runDemo();
                runFixedLengthDemo();
            } else if (args[0].equalsIgnoreCase("mac") && args.length == 3) 
            {
                byte[] key = hexToBytes(args[1]);
                byte[] msg = hexToBytes(args[2]);
                System.out.println("Computed Tag: " + bytesToHex(mac(key, msg)));
            } else if (args[0].equalsIgnoreCase("verify") && args.length == 4) 
            {
                byte[] key = hexToBytes(args[1]);
                byte[] msg = hexToBytes(args[2]);
                byte[] tag = hexToBytes(args[3]);
                System.out.println("Verification Result: " + verify(key, msg, tag));
            } else if (args[0].equalsIgnoreCase("forge") && args.length == 2) 
            {
                byte[] target = args[1].getBytes(StandardCharsets.UTF_8);
                Oracle o = new Oracle(null);
                byte[] tag = forge(o::query, target);
                System.out.println("Target ASCII   : " + args[1]);
                System.out.println("Target Blocks  : " + (target.length / 16));
                System.out.println("Forged Tag     : " + bytesToHex(tag));
                System.out.println("Queries Made   : " + o.queries.size());
                System.out.println("Target Queried?: " + o.queries.contains(bytesToHex(target)));
                System.out.println("Forgery Valid? : " + o.verifyTarget(target, tag));
            } else 
            {
                System.out.println("Usage:");
                System.out.println("  java CBCMAC                            (Runs default assignment demo)");
                System.out.println("  java CBCMAC mac <keyHex> <msgHex>");
                System.out.println("  java CBCMAC verify <keyHex> <msgHex> <tagHex>");
                System.out.println("  java CBCMAC forge \"<ASCII string of multiple of 16 bytes>\"");
            }
        } catch (Exception e) 
        {
            e.printStackTrace();
            System.exit(1);
        }
    }
}