import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.jetbrains.annotations.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Class that contains both the Hashtree structure and Signature data
 * @author F. Krause, 17575 SMSB HOST
 */
public class Merkle {

    static final double ln2 = Math.log(2);

    private ArrayList<byte[]> leaves;
    private ArrayList<String> dict;

    private MessageDigest hash;
    private static final SecureRandom srand = new SecureRandom();
    private final Signature ecdsa;

    private HashTree tree;

    private @Nullable Base64URL signature;

    /**
     * Getter for signature
     * @return ecdsa signature over root hash (SHA256) encoded as Base64 URL
     */
    public @Nullable Base64URL getSignature() {

        return this.signature;
    }

    public @Nullable Base64 cert;

    /**
     * Getter for Certificate
     * @return X.509 certificate encoded in Base64
     */
    public @Nullable Base64 getCert() {

        return this.cert;
    }

    private boolean closed, initiated;

    /**
     * Getter for Status of Object
     * @return -1 if uninitialised, 0 if initiated but not closed, 1 if closed
     */
    public int getStatus() {

        if (!initiated) return -1;
        if (!closed) return 0;
        else return 1;
    }

    /**
     * Constructor
     * initiates Lists, instantiates Factories and sets base values for closed, initiated (false)
     * @throws NoSuchAlgorithmException if I misspelled one of the Algorithms
     */
    public Merkle() throws NoSuchAlgorithmException {

        this.leaves = new ArrayList<>();
        this.dict = new ArrayList<>();

        this.hash = MessageDigest.getInstance("SHA-256");
        this.ecdsa = Signature.getInstance("SHA256withECDSA");

        this.closed = false;
        this.initiated = false;

        this.tree = null;
        this.signature = null;
        this.cert = null;
    }

    /**
     * Constructor with immediate initialisation
     * @param keyFile File containing key data
     * @param certFile File containing Certificate data
     * @throws NoSuchAlgorithmException if I misspelled my algs
     */
    public Merkle(File keyFile, File certFile) throws NoSuchAlgorithmException {

        this();
        this.init(keyFile, certFile);
    }

    /**
     * initialisation of Key and Certificate for signing
     * @param keyFile File containing key data
     * @param certFile File containing Certificate data
     * @throws NoSuchAlgorithmException if I have a typo in my algorithms
     */
    public void init(File keyFile, File certFile) throws NoSuchAlgorithmException {
        if (this.closed) throw new IllegalStateException("This Structure is already closed and signed");

        try {

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile.toPath()));

            ECPrivateKey eckey =(ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(spec);
            ecdsa.initSign(eckey, srand);
            X509Certificate eccert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certFile));

            this.cert = Base64.encode(eccert.getEncoded());
            this.initiated = true;

        } catch (IOException e) {

            System.err.println("Unable to read File(s)");
            e.printStackTrace();

            this.cert = null;
            this.initiated = false;

        } catch (InvalidKeySpecException | InvalidKeyException e) {

            System.err.println("Unable to parse key");
            e.printStackTrace();

            this.cert = null;
            this.initiated = false;

        } catch (CertificateException e) {

            System.err.println("Unable to parse Certificate");
            e.printStackTrace();

            this.cert = null;
            this.initiated = false;
        }
    }

    /**
     * generate string of hex values that represents the byte array
     * (for use in leaves)
     * @param bytes input
     * @return output
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder buf = new StringBuilder();
        for (byte b : bytes) {
            String str = Integer.toHexString(Byte.toUnsignedInt(b));
            buf.append(str);
        }
        return buf.toString();
    }

    /**
     * Returns the order index, aka what turn it is added into the tree when inserting all the messages (starting at 0)
     * @param msg message to search for
     * @return order index of the given message in this tree, or -1 if it is not contained
     */
    public int lookup(byte[] msg) {
        return this.dict.indexOf(bytesToHex(hash.digest(msg)));
    }

    /**
     * add node to leaves
     * @param msg raw bytes
     * @throws IllegalStateException if this structure is already closed
     */
    public void add(byte[] msg) throws IllegalStateException {
        if (this.closed) throw new IllegalStateException("This Structure is closed and signed already");

        byte[] ham = hash.digest(msg);

        leaves.add(ham);

        leaves.add(new byte[32]);
        srand.nextBytes(leaves.get(leaves.size() - 1));

        dict.add(bytesToHex(ham));
    }

    /**
     * bulk add nodes to leaves
     * @param list list of raw byte-array messages to sign
     * @throws IllegalStateException if this structure is already closed
     */
    public void addAll(Collection<byte[]> list) throws IllegalStateException {

        for (byte[] b : list) this.add(b);
    }

    /**
     * close and sign, generating tree and signature attribute
     * @throws IllegalStateException if this structure is already closed or has not been initialised for signing
     * @throws NoSuchAlgorithmException if I have a typo in my algs
     */
    public void closeAndSign() throws IllegalStateException, NoSuchAlgorithmException {
        if (this.closed) throw new IllegalStateException("This Structure is closed and signed already");
        if (!this.initiated) throw new IllegalStateException("No Key has been initiated");

        try {
            this.tree = new HashTree(this.leaves);
            ecdsa.update(tree.getRoot());
            this.signature = Base64URL.encode(ecdsa.sign());
            this.closed = true;

        } catch (ConcatException e) {

            System.err.println("Failed to build Tree");
            e.printStackTrace();

            this.tree = null;
            this.closed = false;

        } catch (SignatureException e) {

            this.signature = null;
            this.tree = null;
            this.closed = false;
            this.initiated = false;

            throw new IllegalStateException("Key has not been initiated properly", e);
        }
    }

    /**
     * concatenate byte arrays (order left to right) into one
     * @param left left bytes
     * @param right right bytes
     * @return resulting byte array
     * @throws ConcatException if there is a glitch during concatenation
     */
    static byte[] concat(byte[] left, byte[] right) throws ConcatException {
        try {

            ByteArrayOutputStream outp = new ByteArrayOutputStream();
            outp.write(left);
            outp.write(right);
            return outp.toByteArray();

        } catch (IOException e) {

            throw new ConcatException(e);
        }
    }

    /**
     * concatenate two byte arrays (left to right order) and SHA-256-hash the result
     * @param left left bytes
     * @param right right bytes
     * @return byte array of size 32, containing the hash over the concatenated input bytes
     * @throws ConcatException if there is a glitch during concatenation
     * @throws NoSuchAlgorithmException if I misspelled SHA-256
     */
    static byte[] concatHash(byte[] left, byte[] right) throws ConcatException, NoSuchAlgorithmException {

        MessageDigest sha = MessageDigest.getInstance("SHA-256");

        return sha.digest(concat(left, right));
    }

    /**
     * custom Exception class for concatenation processes
     * thrown if the concatenation process glitches
     */
    static class ConcatException extends Exception{

        /**
         * basic constructor
         * @param errorMsg Message
         * @param err Cause
         */
        public ConcatException(String errorMsg, Throwable err) {

            super(errorMsg, err);
        }

        /**
         * additional constructor to construct from a base Exception
         * @param e Exception to cloak
         */
        public ConcatException(Exception e) {

            this(e.getMessage(), e.getCause());
        }
    }

    /**
     * Hashtree structure class
     * contains a 4-D Array of bytes
     * rows[a][b][c]
     * a
     * 3                                   hash()
     *                                  /        \
     *                                /           \
     *                              /              \
     *                            /                 \
     *                          /                    \
     *                        /                       \
     * 2               hash()                          hash()
     *              /         \                     /         \
     *            /            \                  /            \
     *          /               \               /               \
     * 1      hash()           hash()          hash()         hash()
     *      /       \        /       \       /       \      /       \
     *   c 0 1..    0 1..    ..
     * 0 b'F1A..' b'02f..' b'..'  b'..'   b'..'   b'..'   b'..'   b'..'
     * b    0       1       2       3       4       5       6       7
     */
    private static class HashTree {
        public byte[][][] rows;

        /**
         * Constructor
         * builds a complete binary hashtree using the given leaves
         * @param leaves set of leaves
         * @throws ConcatException if the calculation glitches during concatenation
         * @throws NoSuchAlgorithmException if I misspelled SHA-256
         */
        public HashTree(ArrayList<byte[]> leaves) throws ConcatException, NoSuchAlgorithmException {

            int rcount = (int) Math.ceil(Math.log(leaves.size()) / ln2) + 1;
            this.rows = new byte[rcount][][];

            this.rows[0] = new byte[(int) Math.pow(2, rcount - 1)][32];
            int offset = leaves.size();
            leaves.toArray(this.rows[0]);

            while (offset < Math.pow(2, rcount -1)) {

                rows[0][offset] = new byte[32];
                srand.nextBytes(rows[0][offset]);
                offset++;
            }

            for (int i = 0; i < (rcount - 1); i++) {

                rows[i + 1] = new byte[rows[i].length / 2][];

                int j = 0;
                do {
                    rows[i + 1][j] = concatHash(
                            rows[i][j * 2],
                            rows[i][(j * 2) + 1]
                    );
                    j++;

                } while (j < (rows[i].length / 2));
            }
        }

        public byte[] getRoot() {
            return this.rows[this.rows.length - 1][0];
        }
    }

    /**
     * Getter for the Path to root along which a given message can be found's Neighbours in the Hashtree
     * @param msg message to search for
     * @return Array of Base64-URL-Strings representing each hash
     * @throws IllegalStateException if this structure has yet to be closed
     * @throws ConcatException if the Concatenation glitches
     */
    String[] getPath(byte[] msg) throws IllegalStateException, IllegalArgumentException, ConcatException {
        if (!this.closed) throw new IllegalStateException("Tree has yet to be built");
        if (lookup(msg) == -1) throw new IllegalArgumentException("message not contained in this tree");

        int offset = lookup(msg) * 2;
        if (offset < 0) throw new IllegalArgumentException("Message not contained in this tree");

        ArrayList<String> hashes = new ArrayList<>();
        for (byte[][] row : tree.rows) {

            if (row.length == 1) break;
            if (offset % 2 == 1)
                hashes.add(Base64URL.encode(concat("-".getBytes(StandardCharsets.UTF_8), row[offset - 1])).toString());
            else
                hashes.add(Base64URL.encode(row[offset + 1]).toString());

            offset /= 2;
        }

        return hashes.toArray(new String[hashes.size()]);
    }
}
