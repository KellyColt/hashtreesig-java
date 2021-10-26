import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;

public class Signature {
    private static final int test_nr = 3;

    public static void main(String[] args) throws CertificateException, InvalidKeyException {
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

        String json_string = merkle.json_web_signature(msg);
        System.out.println(json_string);
        String[] b64strings = json_string.split("\\.");

        for (String s : b64strings) {

            String str = new String(
                    Base64.getDecoder().decode(s.getBytes(StandardCharsets.UTF_8)),
                    StandardCharsets.UTF_8
            );

            System.out.println(str);
        }
        if (HashTree.verifyjws(json_string))
            System.out.println("signature verified");
        else System.out.println("verification failed");

    }
}
