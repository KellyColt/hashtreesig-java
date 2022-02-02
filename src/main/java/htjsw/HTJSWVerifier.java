package htjsw;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.jetbrains.annotations.Nullable;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;

// @TODO test with wrong signatures
/*
 *    hashtreesig, a GUI for signing multiple Files using a Merkle Hash Tree and EC-SHA256
 *    Copyright (C) 2022  F. Krause
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * Verifier implementing the JWSVerifier from nimbusds' jose implementation
 * @author F. Krause
 */
public class HTJSWVerifier implements JWSVerifier {

    /**
     * Certificate used for verification
     */
    private @Nullable X509Certificate cert;

    /**
     * Constructor for Verifier without dedicated Certificate
     */
    public HTJSWVerifier() {

        this.cert = null;
    }

    /**
     * Constructor with Certificate
     * @param cert X.509 Certificate
     * @throws CertificateException if cert is not valid
     */
    public HTJSWVerifier(Certificate cert) throws CertificateException {

        this.cert = (X509Certificate) cert;
        this.cert.checkValidity();
    }

    /**
     * Constructor that reads a File into the Verifier's dedicated Certificate
     * @param certFile File containing X.509 Certificate
     * @throws CertificateException if Certificate is invalid
     * @throws IOException if File cannot be read
     */
    public HTJSWVerifier(File certFile) throws CertificateException, IOException {

        this(
                CertificateFactory.getInstance("X.509").generateCertificate(
                        new FileInputStream(certFile)
                )
        );
    }

    /**
     * Setter that reads Certificate into Verifier from File
     * @param certFile File containing X.509 Certificate
     * @throws CertificateException if Certificate is invalid
     * @throws IOException if File cannot be read
     */
    public void setCert(File certFile) throws CertificateException, IOException {

        setCert(
                CertificateFactory.getInstance("X.509").generateCertificate(
                        new FileInputStream(certFile)
                )
        );
    }

    /**
     * Setter that determines the Verifier's dedicated Certificate
     * @param cert X.509 Certificate
     * @throws CertificateException if cert is invalid
     */
    public void setCert(Certificate cert) throws CertificateException {

        this.cert = (X509Certificate) cert;
        this.cert.checkValidity();
    }

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

            X509Certificate certificate;
            if (this.cert != null &&
                    Base64.encode(this.cert.getEncoded())
                            .equals(
                                    header.getX509CertChain().get(0)
                            )
            )  certificate = this.cert;
            else {

                //parse certificate from header
                ByteArrayOutputStream certstrm = new ByteArrayOutputStream();

                for (Base64 link : header.getX509CertChain())
                    certstrm.write(link.decode());

                ByteArrayInputStream inputStream = new ByteArrayInputStream(certstrm.toByteArray());
                certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
                certificate.checkValidity();
            }

            //initialise Signature Object for verification
            Signature versig = Signature.getInstance("SHA256withECDSA");
            versig.initVerify(certificate.getPublicKey());

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
            for (byte[] hash : path)
                if (hash[0] == (byte) '-')
                    msghash = Merkle.concatHash(Arrays.copyOfRange(hash, 1, hash.length), msghash);
                else
                    msghash = Merkle.concatHash(msghash, hash);

            //verify root signature using root hash
            versig.update(msghash);
            return versig.verify(Base64URL.from(sig.getString("ecdsa_sig")).decode());

        } catch (Merkle.ConcatException e) {

            System.err.println("Concat Error");
            e.printStackTrace();
            throw new JOSEException("Failed to calculate root");

        } catch (IOException | CertificateException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {

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
