

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;

public class Signature {
    private static final int test_nr = 3;
    private static final Base64.Decoder dec = Base64.getDecoder();
    private static final Base64.Encoder enc = Base64.getEncoder();

    public static void main(String[] args) throws CertificateException, IOException {
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

        ByteArrayOutputStream jsonstrm = new ByteArrayOutputStream();

        jsonstrm.write(merkle.header());
        jsonstrm.write(".".getBytes(StandardCharsets.UTF_8));
        jsonstrm.write(Base64.getEncoder().encode(msg));
        jsonstrm.write(".".getBytes(StandardCharsets.UTF_8));
        jsonstrm.write(merkle.signature(msg));

        byte[] json_web_signature = jsonstrm.toByteArray();

        System.out.println(new String(json_web_signature, StandardCharsets.UTF_8));

        String json_string = new String(json_web_signature, StandardCharsets.UTF_8);
        String[] b64strings = json_string.split("\\.");
        ArrayList<byte[]> b64bytes = new ArrayList<>();
        for (String s : b64strings) {

            byte[] str = Base64.getDecoder().decode(
                    s.getBytes(StandardCharsets.UTF_8)
            );
            b64bytes.add(str);
            System.out.println(new String(str, StandardCharsets.UTF_8));
        }
    }
}
