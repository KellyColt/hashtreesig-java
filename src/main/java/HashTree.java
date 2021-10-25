import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

import org.json.JSONArray;
import org.json.JSONObject;

public class HashTree {
    public boolean closed;
    private ArrayList<String> leaves;
    private ArrayList<ArrayList<byte[]>> nodes;
    public byte[] ecdsa_sig;
    private ECPrivateKey key;
    private Certificate cert;
    private MessageDigest digest;
    private SecureRandom srand;
    private Base64.Encoder b64enc;

    public HashTree(File keyFile, File certFile) throws IOException, CertificateException {
        this.closed = false;
        this.leaves = new ArrayList<>();

        this.nodes = new ArrayList<>();
        nodes.add(new ArrayList<>());

        this.srand = new SecureRandom();
        this.b64enc = Base64.getEncoder();

        this.cert = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certFile));
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
        byte[] hash = digest.digest(msg);
        leaves.add(bytesToHex(hash));
        nodes.get(0).add(hash);
        byte[] token = new byte[32];
        srand.nextBytes(token);
        nodes.get(0).add(token);
    }

    public void sign() throws IllegalStateException{
        if (this.closed) throw new IllegalStateException("this tree is already closed");
        ArrayList<byte[]> l0 = nodes.get(0);
        int power2 = (int) Math.ceil(Math.log(l0.size()) / Math.log(2));
        int missing = (int) Math.pow(2,  power2) - l0.size();
        for (int i = 0; i < missing; i++) {
            byte[] token = new byte[32];
            srand.nextBytes(token);
            l0.add(token);
        }

        ArrayList<byte[]> last = nodes.get(nodes.size() - 1);
        if (!last.equals(l0))
            throw new IllegalStateException("Something went real wrong babes");
        else if(last.isEmpty())
            throw new IllegalStateException("no messages to sign");
        else if(last.size() > 1)
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
        StringBuilder buf = new StringBuilder();
        for (byte b : bytes) {
            String str = Integer.toHexString(Byte.toUnsignedInt(b));
            buf.append(str);
        }
        return buf.toString();
    }

    public byte[] header() throws CertificateEncodingException {
        JSONObject header = new JSONObject()
                .put("alg", "HTES256")
                .put("x5c", new String(
                        b64enc.encode(
                                this.cert.getEncoded()
                        ),
                        StandardCharsets.UTF_8
                ));

        return b64enc.encode(header.toString().getBytes(StandardCharsets.UTF_8));
    }

    public  String b64utfstr(byte[] bytes) {
        return new String(
                b64enc.encode(bytes),
                StandardCharsets.UTF_8
        );
    }

    public byte[] signature(byte[] msg) {
        if(!this.closed) throw new IllegalStateException("Hashtree is not signed yet");

        byte[] hashedmsg = digest.digest(msg);
        String hash = bytesToHex(hashedmsg);

        if(!leaves.contains(hash)) throw new IllegalArgumentException("Message not contained in this Hashtree");

        ArrayList<String> hashList = new ArrayList<>();
        int offset = leaves.indexOf(hash) * 2;

        for (ArrayList<byte[]> layer : nodes.subList(0, nodes.size() - 1)) {

            if(offset % 2 == 0)
                hashList.add(b64utfstr(layer.get(offset + 1)));
            else
                hashList.add(b64utfstr(layer.get(offset - 1)));

            offset /= 2;
        }

        JSONObject signature = new JSONObject()
                .put("ht_path", hashList)
                .put("ecdsa_sig", b64utfstr(this.ecdsa_sig));

        return(b64enc.encode(signature.toString().getBytes(StandardCharsets.UTF_8)));
    }
}
