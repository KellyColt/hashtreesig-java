import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class HashTree {
    public boolean closed;
    private ArrayList<byte[]> leaves;
    private ArrayList<ArrayList<byte[]>> nodes;
    public byte[] ecdsa_sig;
    private ECPrivateKey key;
    private MessageDigest digest;
    private SecureRandom srand;

    public HashTree(File keyFile) throws IOException {
        this.closed = false;
        this.leaves = new ArrayList<>();

        this.nodes = new ArrayList<>();
        this.nodes.add(leaves);

        this.srand = new SecureRandom();

        // this.cert = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(keyFile));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile.toPath()));
        try {
            this.key =(ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(spec);
            this.digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Instantiation Error: Algorithm");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("your spec is invalid you absolute fucking idiot");
            e.printStackTrace();
        }
    }

    public void add(byte[] msg) throws IllegalStateException{
        if (this.closed) throw new IllegalStateException("this hashtree is closed");
        leaves.add(digest.digest(msg));
        byte[] token = new byte[32];
        srand.nextBytes(token);
        leaves.add(token);
    }

    public void sign() throws IllegalStateException{
        if (this.closed) throw new IllegalStateException("this tree is already closed");

        int power2 = (int) Math.ceil(Math.log(this.leaves.size()) / Math.log(2));
        int missing = (int) Math.pow(2,  power2) - this.leaves.size();
        for (int i = 0; i < missing; i++) {
            byte[] token = new byte[32];
            srand.nextBytes(token);
            leaves.add(token);
        }
        ArrayList<byte[]> last = nodes.get(nodes.size() - 1);
        if (!last.equals(leaves)) throw new IllegalStateException("Something went real wrong babes");
        else if(last.isEmpty()) throw new IllegalStateException("no messages to sign");
        else if(last.size() > 1) {
            do {
                ArrayList<byte[]> neu = new ArrayList<>();
                for (int i = 0; i < last.size(); i += 2) {
                    try {
                        ByteArrayOutputStream outp = new ByteArrayOutputStream();
                        outp.write(last.get(i));
                        outp.write(last.get(i + 1));
                        neu.add(digest.digest(outp.toByteArray()));
                    } catch (IOException e) {
                        System.err.println("concat error");
                        e.printStackTrace();
                        return;
                    }
                }
                nodes.add(neu);
                last = neu;
            } while (last.size() != 1);
        }
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(key, srand);
            signature.update(last.get(0));
            this.ecdsa_sig = signature.sign();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Signature Algorithm Instantiation Error");
            e.printStackTrace();
            return;
        } catch (InvalidKeyException e) {
            System.err.println("Invalid Key Exception at signature initialisation");
            e.printStackTrace();
            return;
        } catch (SignatureException e) {
            System.err.println("Error in signing process");
            e.printStackTrace();
            return;
        }

        this.closed = true;
    }

    public String bytesToHex(byte[] bytes) {
        StringBuffer buf = new StringBuffer();
        for (byte b : bytes) {
            String str = Integer.toHexString(Byte.toUnsignedInt(b));
            buf.append(str);
        }
        return buf.toString();
    }
}
