import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;

/**
 * Currently a debugging executable class
 * @author F. Krause, SMSB HOST
 */
public class Signature {
    private static final int test_nr = 3;

    /**
     * runnable
     * @param args parameters
     * @throws JOSEException if verification error occurs
     */
    public static void main(String[] args) throws JOSEException {
        System.out.println("Hello World");

        File certFile = new File("pki/signer_cert.der");
        File keyFile = new File("pki/signing_key.der");
        HashTree merkle;
        try {
            merkle = new HashTree(keyFile, certFile);
        } catch (IOException e) {
            System.err.println("Error reading Keyfile");
            e.printStackTrace();
            return;
        } catch (CertificateException e) {
            System.err.println("Error reading Certificate");
            e.printStackTrace();
            return;
        }
        System.out.printf("Ich erzeuge ad-hoc %d Nachrichten %n", test_nr);

        for (int i = 0; i < test_nr; i++) {
            byte[] msg = ("Hallo, ich bin Nachricht Nr. " + i).getBytes(StandardCharsets.UTF_8);
            merkle.add(msg);
            System.out.println("Added message " + i);
        }

        merkle.sign();

        byte[] msg = "Hallo, ich bin Nachricht Nr. 2".getBytes(StandardCharsets.UTF_8);

        JWSObject json_string = merkle.json_web_signature(msg);
        System.out.println(json_string);
        System.out.println(json_string.getHeader().toString());
        System.out.println(json_string.getPayload().toString());
        System.out.println(json_string.getSignature().decodeToString());

        System.out.println(json_string.verify(new HTES256Verifier()));
    }
}
