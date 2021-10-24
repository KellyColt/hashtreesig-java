import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.HashMap;

public class HashTree {
    public boolean closed;
    public ArrayList<byte[]> leaves;
    public ArrayList<byte[]> nodes;
    public final byte[] ecdsa_sig;
    private Certificate cert;

    public HashTree(File certFile) throws CertificateException, FileNotFoundException {
        this.closed = false;
        this.leaves = new ArrayList<>();

        this.nodes = new ArrayList<>();
        this.ecdsa_sig = new byte[32];

        this.cert = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certFile));
    }
}
