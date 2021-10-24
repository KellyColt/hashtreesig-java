import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Signature {
    private static final int test_nr = 3;

    public static void main(String[] args) {
        System.out.println("Hello World");

        // File certFile = new File("pki/signer_cert.der");
        File keyFile = new File("pki/signing_key.der");
        HashTree merkle;
        try {
            merkle = new HashTree(keyFile);
        } catch (IOException e) {
            System.err.println("Error reading Keyfile");
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
        System.out.println(merkle.bytesToHex(merkle.ecdsa_sig));
    }
}
