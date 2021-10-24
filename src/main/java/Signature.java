import java.io.File;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;

public class Signature {
    private static int test_nr = 3;
    public static void main(String[] args) {
        System.out.println("Hello World");

        File certFile = new File("pki/signer_cert.der");
        HashTree merkle;
        try {
            merkle = new HashTree(certFile);
        } catch (CertificateException e) {
            System.err.println("Invalid Certificate");
            e.printStackTrace();
            return;
        } catch (FileNotFoundException e) {
            System.err.println("Certificate File not Found");
            e.printStackTrace();
            return;
        }
        System.out.printf("Ich erzeuge ad-hoc %d Nachrichten %n", test_nr);

        for (int i = 0; i < test_nr; i++) {

        }
    }
}
