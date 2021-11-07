import com.nimbusds.jose.*;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

/**
 * Verifier implementing the JWSVerifier from nimbusds' jose implementation
 * @author F. Krause, SMSB HOST
 */
public class HTES256Verifier implements JWSVerifier {

    /**
     * verification algorithm for a JWS with Hashtree ECDSA SHA256 signature
     * @param header Header of the JWS
     * @param signingInput the JWS "signing input",
     *                     containing Header and Payload encoded as Base64URL in Header.Payload format,
     *                     as byte data
     * @param signature Base64URL encrypted Signature part of the JWS
     * @return true if verification successful
     * @throws JOSEException if anything goes wrong during verification (see error messages)
     */
    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {

        if (!header.getAlgorithm().equals(JWSAlgorithm.parse("HTES256"))) throw new JOSEException("invalid algorithm");

        try {
            //parse certificate from header
            ByteArrayOutputStream certstrm = new ByteArrayOutputStream();
            for (Base64 link : header.getX509CertChain())
                certstrm.write(link.decode());
            ByteArrayInputStream inputStream = new ByteArrayInputStream(certstrm.toByteArray());
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
            cert.checkValidity();

            //initialise Signature Object for verification
            Signature versig = Signature.getInstance("SHA256withECDSA");
            versig.initVerify(cert.getPublicKey());

            //load message from signing Input
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            Payload msg = new Payload(new Base64URL(new String(signingInput, StandardCharsets.UTF_8).split("\\.")[1]));
            byte[] msghash = digest.digest(msg.toBytes());

            //parse signature
            JSONObject sig = new JSONObject(signature.decodeToString());
            JSONArray jsnpath = sig.getJSONArray("ht_path");
            String[] b64path = Arrays.copyOf(jsnpath.toList().toArray(), jsnpath.length(), String[].class);

            byte[][] path = new byte[b64path.length][];
            for (int i = 0; i < b64path.length; i++)
                path[i] = Base64URL.from(b64path[i]).decode();

            //calculate root hash
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

            //verify root signature using root hash
            versig.update(msghash);
            return versig.verify(Base64URL.from(sig.getString("ecdsa_sig")).decode());

        } catch (IOException e) {

            System.err.println("Concat Error");
            e.printStackTrace();
            throw new JOSEException("");

        } catch (CertificateException |InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {

            e.printStackTrace();
            throw new JOSEException("Certificate Instantiation error");
        }

    }

    //not able to implement since JWSAlgorithm is final
    /**
     * implementation of identification method
     * @return null
     */
    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return null;
    }

    //unnecessary
    /**
     * implementation of information method
     * @return null
     */
    @Override
    public JCAContext getJCAContext() {
        return null;
    }
}
