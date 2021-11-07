import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Signature;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;

// @TODO clean up and split
/**
 * Hash Tree class
 * @author F. Krause, SMSB HOST
 */
public class HashTree {
    public boolean closed;
    private ArrayList<String> leaves;
    private ArrayList<ArrayList<byte[]>> nodes;
    public byte[] ecdsa_sig;
    private ECPrivateKey key;
    private final Certificate cert;
    private MessageDigest digest;
    private final SecureRandom srand;

    /**
     * only Constructor
     * @param keyFile File Object for private key
     * @param certFile File Object for certificate
     * @throws IOException thrown if key file cannot be read
     * @throws CertificateException thrown if certificate cannot be parsed
     */
    public HashTree(File keyFile, File certFile) throws IOException, CertificateException {
        this.closed = false;
        this.leaves = new ArrayList<>();

        this.nodes = new ArrayList<>();
        nodes.add(new ArrayList<>());

        this.srand = new SecureRandom();

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

    /**
     * adds a bytearray of data to sign
     * @param msg data to sign
     * @throws IllegalStateException thrown if Tree is already closed and signed
     */
    public void add(byte[] msg) throws IllegalStateException{
        if (this.closed) throw new IllegalStateException("this hashtree is closed");
        byte[] hash = digest.digest(msg);
        leaves.add(bytesToHex(hash));
        nodes.get(0).add(hash);
        byte[] token = new byte[32];
        srand.nextBytes(token);
        nodes.get(0).add(token);
    }

    /**
     * closes and generates root signature
     * @throws IllegalStateException thrown if tree is already closed
     */
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
            throw new IllegalStateException("Something went real wrong babes"); //@TODO implement re-try for when signing failed once and left behind erroneous nodes
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

                        neu.add(
                                digest.digest(
                                        outp.toByteArray()
                                )
                        );

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

    /**
     * generate string of hex values that represents the byte array
     * (for use in leaves)
     * @param bytes input
     * @return output
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder buf = new StringBuilder();
        for (byte b : bytes) {
            String str = Integer.toHexString(Byte.toUnsignedInt(b));
            buf.append(str);
        }
        return buf.toString();
    }

    /**
     * JSON data for Signature header (algorithm, and certificate with Base64 Encoding)
     * @return Base64URL encoded JSON Object String representation
     */
    public Base64URL jwsheader() {
        try {
            JSONObject header = new JSONObject()
                    .put("alg", "HTES256")
                    .put("x5c", new String[]{
                            Base64.encode(
                                    this.cert.getEncoded()
                            ).toString()});

            return Base64URL.encode(header.toString());
        } catch (CertificateException e) {

            System.err.println("Certificate output Error");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * JSON form signature
     * (Sibling Node Hashes on path to root, individually b64-encoded, with a plaintext '-' if left sibling,
     * root signature with Base64 encoding) for the given message
     * @param msg raw data of leaf node within this Tree
     * @return Base64URL encoded JSON Object String representation
     * @throws IllegalStateException thrown if this Tree has yet to be closed and signed
     * @throws IllegalArgumentException thrown if the given message cannot be found in this Tree's leaves
     */
    public Base64URL signature(byte[] msg) throws IllegalStateException, IllegalArgumentException {
        if(!this.closed) throw new IllegalStateException("Hashtree is not signed yet");

        byte[] hashedmsg = digest.digest(msg);
        String hash = bytesToHex(hashedmsg);

        if(!leaves.contains(hash)) throw new IllegalArgumentException("Message not contained in this Hashtree");

        ArrayList<String> hashList = new ArrayList<>();
        int offset = leaves.indexOf(hash) * 2;

        for (ArrayList<byte[]> layer : nodes.subList(0, nodes.size() - 1)) {

            if (offset % 2 == 1) {
                try {

                    ByteArrayOutputStream stream = new ByteArrayOutputStream();
                    stream.write("-".getBytes(StandardCharsets.UTF_8));
                    stream.write(layer.get(offset - 1));
                    hashList.add(Base64URL.encode(stream.toByteArray()).toString());

                } catch (IOException e) {

                    System.err.println("concat error");
                    e.printStackTrace();
                    return null;
                }
            } else
                hashList.add(Base64URL.encode(layer.get(offset + 1)).toString());

            offset /= 2;
        }

        JSONObject signature = new JSONObject()
                .put("ht_path", hashList)
                .put("ecdsa_sig", Base64URL.encode(this.ecdsa_sig).toString());

        return(Base64URL.encode(signature.toString()));
    }

    /**
     * serialise JWS
     * @param msg message to generate signature for
     * @return JWS or null if failed to serialise
     * @throws IllegalStateException if Hashtree isn't closed
     * @throws IllegalArgumentException if msg cannot be found in leaves
     */
    public JWSObject json_web_signature(byte[] msg) throws IllegalStateException, IllegalArgumentException {

        try {
            return new JWSObject(jwsheader(), new Payload(msg), signature(msg));
        } catch (ParseException e) {
            System.err.println("failed to serialise JWS");
            e.printStackTrace();
            return null;
        }
    }
}
