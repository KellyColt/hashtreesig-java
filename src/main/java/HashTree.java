import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.Signature;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

import org.json.JSONException;
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

    public String bytesToHex(byte[] bytes) {
        StringBuilder buf = new StringBuilder();
        for (byte b : bytes) {
            String str = Integer.toHexString(Byte.toUnsignedInt(b));
            buf.append(str);
        }
        return buf.toString();
    }

    public byte[] header() {
        try {
            JSONObject header = new JSONObject()
                    .put("alg", "HTES256")
                    .put("x5c", new String(
                            b64enc.encode(
                                    this.cert.getEncoded()
                            ),
                            StandardCharsets.UTF_8
                    ));

            return b64enc.encode(header.toString().getBytes(StandardCharsets.UTF_8));
        } catch (CertificateException e) {

            System.err.println("Certificate output Error");
            e.printStackTrace();
            return null;
        }
    }

    public  String b64utfstr(byte[] bytes) {
        return new String(
                b64enc.encode(bytes),
                StandardCharsets.UTF_8
        );
    }

    public byte[] signature(byte[] msg) throws IllegalStateException, IllegalArgumentException {
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
                    hashList.add(b64utfstr(stream.toByteArray()));

                } catch (IOException e) {

                    System.err.println("concat error");
                    e.printStackTrace();
                    return null;
                }
            } else
                hashList.add(b64utfstr(layer.get(offset + 1)));

            offset /= 2;
        }

        JSONObject signature = new JSONObject()
                .put("ht_path", hashList)
                .put("ecdsa_sig", b64utfstr(this.ecdsa_sig));

        return(b64enc.encode(signature.toString().getBytes(StandardCharsets.UTF_8)));
    }

    public String json_web_signature(byte[] msg) {

        ByteArrayOutputStream jsonstrm = new ByteArrayOutputStream();

        try {

            jsonstrm.write(this.header());
            jsonstrm.write(".".getBytes(StandardCharsets.UTF_8));
            jsonstrm.write(Base64.getEncoder().encode(msg));
            jsonstrm.write(".".getBytes(StandardCharsets.UTF_8));
            jsonstrm.write(this.signature(msg));

        } catch (IOException e) {

            System.err.println("concat error");
            e.printStackTrace();
            return null;
        }

        return jsonstrm.toString(StandardCharsets.UTF_8);
    }

    public static boolean verifyjws(String jws) throws CertificateException, InvalidKeyException {
        String[] split = jws.split("\\.");
        Base64.Decoder dec = Base64.getDecoder();


        try {

            JSONObject header = new JSONObject(new String(dec.decode(split[0]), StandardCharsets.UTF_8));
            JSONObject signature = new JSONObject(new String(dec.decode(split[2].getBytes(StandardCharsets.UTF_8))));

            byte[] sig = dec.decode(signature.getString("ecdsa_sig").getBytes(StandardCharsets.UTF_8));

            List<Object> pathlist = signature.getJSONArray("ht_path").toList();
            String[] b64path = Arrays.copyOf(pathlist.toArray(new Object[0]), pathlist.size(), String[].class);

            byte[][] decpath = new byte[b64path.length][];
            for (int i = 0; i < b64path.length; i++)
                decpath[i] = dec.decode(b64path[i].getBytes(StandardCharsets.UTF_8));

            return(verifysig(
                    dec.decode(header.getString("x5c").getBytes(StandardCharsets.UTF_8)),
                    decpath,
                    dec.decode(split[1].getBytes(StandardCharsets.UTF_8)),
                    sig)
            );

        } catch (JSONException | IndexOutOfBoundsException e) {

            System.err.println("Invalid Format");
            e.printStackTrace();
            return false;
        }
    }

    private static boolean verifysig(byte[] x5c, byte[][] path, byte[] msg, byte[] sig) throws CertificateException, InvalidKeyException {

        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(x5c));
        cert.checkValidity();

        try {

            Signature versig = Signature.getInstance("SHA256withECDSA");
            versig.initVerify(cert.getPublicKey());

            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] msghash = digest.digest(msg);
            for (byte[] hash : path) {
                ByteArrayOutputStream concat = new ByteArrayOutputStream();
                if (hash[0] == (byte) '-') {
                    concat.write(Arrays.copyOfRange(hash, 1, hash.length));
                    concat.write(msghash);
                } else {
                    concat.write(msghash);
                    concat.write(hash);
                }
                msghash = digest.digest(concat.toByteArray());
            }

            versig.update(msghash);
            return versig.verify(sig);

        } catch (IOException e) {

            System.err.println("concat error");
            e.printStackTrace();
            return false;
        } catch (NoSuchAlgorithmException e) {

            System.err.println("instantiation error: Algorithm");
            e.printStackTrace();
            return false;
        } catch (SignatureException e) {

            System.err.println("Signature initialization error");
            e.printStackTrace();
            return false;
        }
    }
}
