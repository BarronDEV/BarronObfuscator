package dev.barron.license;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * License Key Bundle - Contains all encryption parameters
 * fetched from the license server.
 * 
 * These parameters are unique per license and never stored locally.
 */
public class LicenseKeyBundle implements Serializable {

    private static final long serialVersionUID = 1L;

    // Master encryption key (256-bit)
    private final byte[] masterKey;

    // Unique substitution table (256 bytes)
    private final byte[] substitutionTable;

    // XOR layer count (3-10)
    private final int xorLayerCount;

    // Extra XOR keys
    private final byte[][] xorKeys;

    // PBKDF2 iteration count (10K-100K)
    private final int pbkdf2Iterations;

    // Salt for key derivation
    private final byte[] salt;

    // License-specific algorithm variant
    private final int algorithmVariant;

    // Opaque predicate magic numbers
    private final long[] opaquePredicates;

    public LicenseKeyBundle(byte[] masterKey, byte[] substitutionTable,
            int xorLayerCount, byte[][] xorKeys,
            int pbkdf2Iterations, byte[] salt,
            int algorithmVariant, long[] opaquePredicates) {
        this.masterKey = masterKey;
        this.substitutionTable = substitutionTable;
        this.xorLayerCount = xorLayerCount;
        this.xorKeys = xorKeys;
        this.pbkdf2Iterations = pbkdf2Iterations;
        this.salt = salt;
        this.algorithmVariant = algorithmVariant;
        this.opaquePredicates = opaquePredicates;
    }

    /**
     * Generate a random license key bundle for a new license
     */
    public static LicenseKeyBundle generateNew(SecureRandom random) {
        // Master key (32 bytes)
        byte[] masterKey = new byte[32];
        random.nextBytes(masterKey);

        // Substitution table (256 bytes, shuffled)
        byte[] substitutionTable = new byte[256];
        for (int i = 0; i < 256; i++) {
            substitutionTable[i] = (byte) i;
        }
        // Fisher-Yates shuffle
        for (int i = 255; i > 0; i--) {
            int j = random.nextInt(i + 1);
            byte temp = substitutionTable[i];
            substitutionTable[i] = substitutionTable[j];
            substitutionTable[j] = temp;
        }

        // XOR layer count (3-10)
        int xorLayerCount = 3 + random.nextInt(8);

        // XOR keys
        byte[][] xorKeys = new byte[xorLayerCount][64];
        for (int i = 0; i < xorLayerCount; i++) {
            random.nextBytes(xorKeys[i]);
        }

        // PBKDF2 iterations (10K-100K)
        int pbkdf2Iterations = 10000 + random.nextInt(90000);

        // Salt (32 bytes)
        byte[] salt = new byte[32];
        random.nextBytes(salt);

        // Algorithm variant (0-15)
        int algorithmVariant = random.nextInt(16);

        // Opaque predicates (8 magic numbers)
        long[] opaquePredicates = new long[8];
        for (int i = 0; i < 8; i++) {
            opaquePredicates[i] = random.nextLong();
        }

        return new LicenseKeyBundle(
                masterKey, substitutionTable, xorLayerCount, xorKeys,
                pbkdf2Iterations, salt, algorithmVariant, opaquePredicates);
    }

    /**
     * Serialize to bytes
     */
    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Write master key
        dos.writeInt(masterKey.length);
        dos.write(masterKey);

        // Write substitution table
        dos.writeInt(substitutionTable.length);
        dos.write(substitutionTable);

        // Write XOR layer count
        dos.writeInt(xorLayerCount);

        // Write XOR keys
        for (byte[] key : xorKeys) {
            dos.writeInt(key.length);
            dos.write(key);
        }

        // Write PBKDF2 iterations
        dos.writeInt(pbkdf2Iterations);

        // Write salt
        dos.writeInt(salt.length);
        dos.write(salt);

        // Write algorithm variant
        dos.writeInt(algorithmVariant);

        // Write opaque predicates
        dos.writeInt(opaquePredicates.length);
        for (long pred : opaquePredicates) {
            dos.writeLong(pred);
        }

        dos.flush();
        return baos.toByteArray();
    }

    /**
     * Deserialize from bytes
     */
    public static LicenseKeyBundle fromBytes(byte[] data) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bais);

        // Read master key
        int masterKeyLen = dis.readInt();
        byte[] masterKey = new byte[masterKeyLen];
        dis.readFully(masterKey);

        // Read substitution table
        int subTableLen = dis.readInt();
        byte[] substitutionTable = new byte[subTableLen];
        dis.readFully(substitutionTable);

        // Read XOR layer count
        int xorLayerCount = dis.readInt();

        // Read XOR keys
        byte[][] xorKeys = new byte[xorLayerCount][];
        for (int i = 0; i < xorLayerCount; i++) {
            int keyLen = dis.readInt();
            xorKeys[i] = new byte[keyLen];
            dis.readFully(xorKeys[i]);
        }

        // Read PBKDF2 iterations
        int pbkdf2Iterations = dis.readInt();

        // Read salt
        int saltLen = dis.readInt();
        byte[] salt = new byte[saltLen];
        dis.readFully(salt);

        // Read algorithm variant
        int algorithmVariant = dis.readInt();

        // Read opaque predicates
        int predCount = dis.readInt();
        long[] opaquePredicates = new long[predCount];
        for (int i = 0; i < predCount; i++) {
            opaquePredicates[i] = dis.readLong();
        }

        return new LicenseKeyBundle(
                masterKey, substitutionTable, xorLayerCount, xorKeys,
                pbkdf2Iterations, salt, algorithmVariant, opaquePredicates);
    }

    // Getters
    public byte[] getMasterKey() {
        return masterKey.clone();
    }

    public byte[] getSubstitutionTable() {
        return substitutionTable.clone();
    }

    public int getXorLayerCount() {
        return xorLayerCount;
    }

    public byte[][] getXorKeys() {
        byte[][] copy = new byte[xorKeys.length][];
        for (int i = 0; i < xorKeys.length; i++) {
            copy[i] = xorKeys[i].clone();
        }
        return copy;
    }

    public int getPbkdf2Iterations() {
        return pbkdf2Iterations;
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public int getAlgorithmVariant() {
        return algorithmVariant;
    }

    public long[] getOpaquePredicates() {
        return opaquePredicates.clone();
    }
}
