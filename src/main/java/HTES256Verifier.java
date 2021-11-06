import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

public class HTES256Verifier implements JWSVerifier {

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {
        if (!header.getAlgorithm().equals(JWSAlgorithm.parse("HTES256"))) throw new JOSEException("invalid algorithm");
        try {

            ByteArrayOutputStream certstrm = new ByteArrayOutputStream();
            for (Base64 link : header.getX509CertChain())
                certstrm.write(link.decode());
            ByteArrayInputStream inputStream = new ByteArrayInputStream(certstrm.toByteArray());
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
            cert.checkValidity();

            Signature versig = Signature.getInstance("SHA256withECDSA");
            versig.initVerify(cert.getPublicKey());

            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] msghash = digest.digest(signingInput);

            JSONObject sig = new JSONObject(signature.decodeToString());
            JSONArray jsnpath = sig.getJSONArray("ht_path");
            String[] b64path = Arrays.copyOf(jsnpath.toList().toArray(), jsnpath.length(), String[].class);

            byte[][] path = new byte[b64path.length][];
            for (int i = 0; i < b64path.length; i++)
                path[i] = java.util.Base64.getDecoder().decode(b64path[i].getBytes(StandardCharsets.UTF_8));

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
            return versig.verify(java.util.Base64.getDecoder().decode(sig.getString("ecdsa_sig").getBytes(StandardCharsets.UTF_8)));

        } catch (IOException e) {

            System.err.println("Concat Error");
            e.printStackTrace();
            throw new JOSEException("");

        } catch (CertificateException |InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {

            e.printStackTrace();
            throw new JOSEException("Certificate Instantiation error");
        }

    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return null;
    }

    @Override
    public JCAContext getJCAContext() {
        return null;
    }

}
