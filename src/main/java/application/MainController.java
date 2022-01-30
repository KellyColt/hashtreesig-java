package application;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import htjsw.HTJSWVerifier;
import htjsw.HTJWSBuilder;
import htjsw.Merkle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import org.jetbrains.annotations.Nullable;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Collection;

/**
 * Controller zwischen Programm und GUI
 * @author F. Krause, SMSB HOST
 */
public class MainController {

    private enum WINDOW{
        FULL,
        MAX,
        COMP
    }

    @FXML private VBox root;
    public MenuBar menu;
    public MenuItem full, comp, max, certs;
    public Button outpDirBut, closeBut, fileSelBut, keySelBut, certSelBut, verify, gen, genfilesel, treesel, genoutp, verSel;

    private File outpDir,  genOutpDir;
    @FXML private TextField outpDirShow, gendirtext;
    @FXML private TextArea sigshow;
    @FXML private Label verifyout;

    @FXML private ListView<File> fileList, GenList;

    @FXML private CheckBox keyCheck, certCheck, treeCheck, sigcheck;
    private @Nullable X509Certificate cert;
    private @Nullable ECPrivateKey key;

    @FXML private Button signBut;
    @FXML private ProgressBar sigProg, genbar;

    private Merkle genTree;
    private JWSObject jws;

    public void initialize() {

        signBut.setOnAction(this::sign);
        gen.setOnAction(this::generate);
        verify.setOnAction(this::verify);

    }

    private void sign(ActionEvent actionEvent) {
        sigProg.setProgress(-1);

        if (!keyCheck.isSelected() || !certCheck.isSelected()) { //@TODO verify if key and cert are a matched pair @TODO implement keystore
            new Alert(Alert.AlertType.ERROR, "No valid key pair has been selected!").showAndWait();
            sigProg.setProgress(0);
            return;
        }

        try {

            Merkle merkle = new Merkle(key, cert);

            sigProg.setProgress(0);
            for (File file : fileList.getItems()) {

                merkle.add(Files.readAllBytes(file.toPath()));
                sigProg.setProgress((1.0 / fileList.getItems().size()) * 0.5);
            }

            merkle.closeAndSign();
            sigProg.setProgress(0.75);

            new FileOutputStream(new File(outpDir, "tree-%d.json".formatted(System.currentTimeMillis())))
                    .write(merkle.serialize().getBytes(StandardCharsets.UTF_8));

            sigProg.setProgress(1);

        } catch (NoSuchAlgorithmException e) {

            e.printStackTrace();
            sigProg.setDisable(true);
            return;

        } catch (IOException e) {
            Alert alert = new Alert(Alert.AlertType.ERROR, "Failed to read file");
            alert.showAndWait();
            e.printStackTrace();
            sigProg.setProgress(0);
            return;
        }
    }

    private void generate(ActionEvent actionEvent) {

        genbar.setProgress(-1);

        if(genTree == null || genOutpDir == null) {

            new Alert(Alert.AlertType.ERROR, "Please select a source File and an output Directory!").showAndWait();
            sigProg.setProgress(0);
            return;
        }

        genbar.setProgress(0);
        double step = (1.0 / GenList.getItems().size()) / 3;

        for (File file : GenList.getItems()) {
            try {

                byte[] msg = Files.readAllBytes(file.toPath());

                genbar.setProgress(genbar.getProgress() + step);

                JWSObject jws = HTJWSBuilder.genJWS(genTree, msg);

                genbar.setProgress(genbar.getProgress() + step);

                new FileOutputStream(
                        new File(
                                genOutpDir,
                                "%s.jws".formatted(file.getName().replace(".", "-"))
                        )
                ).write(jws.serialize().getBytes(StandardCharsets.UTF_8));

                genbar.setProgress(genbar.getProgress() + step);

            } catch (ParseException | IllegalArgumentException | Merkle.ConcatException e) {

                new Alert(Alert.AlertType.ERROR, "failed to generate Signature for File %s".formatted(file.getName()))
                        .showAndWait();
                genbar.setProgress((1.0 / GenList.getItems().size()) * (GenList.getItems().indexOf(file) + 1));

            } catch (IOException e) {

                new Alert(Alert.AlertType.ERROR, "failed to open File %s".formatted(file.getName()))
                        .showAndWait();
                genbar.setProgress((1.0 / GenList.getItems().size()) * (GenList.getItems().indexOf(file) + 1));
            }
        }

        genbar.setProgress(1.0);
    }

    private void verify(ActionEvent actionEvent) {

        try {

            Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(
                            jws.getHeader()
                                    .getX509CertChain()
                                    .get(0)
                                    .decode()
                    )
            );

            if (jws.verify(new HTJSWVerifier())) verifyout.setText("Verification Successful!");
            else verifyout.setText("Verification Failed! Signature invalid!");

        } catch ( JOSEException e) {

            new Alert(Alert.AlertType.ERROR, "failed to perform verification").showAndWait();
            verifyout.setText("Failed to perform Verification");

        } catch (CertificateException e) {

            e.printStackTrace();
            System.err.println("Babe ur Algorithms are soo last saturday");
        }
    }

    public void parseJWS(File file) {

        try {
            jws = JWSObject.parse(Files.readString(file.toPath()));
            sigcheck.setSelected(true);
            sigshow.setText("Certificate: %s".formatted(jws.getHeader().getX509CertChain().get(0).toString()));

        } catch (IOException | ParseException e) {

            new Alert(Alert.AlertType.ERROR, "failed to parse signature file").showAndWait();
            jws = null;
            sigcheck.setSelected(false);
            sigshow.clear();
        }
    }

    public void setOutpDir(@Nullable File file) {

        if (file != null && file.isDirectory()) {

            outpDir = file;
            outpDirShow.setText(outpDir.getAbsolutePath());

        } else {

            outpDir = null;
            outpDirShow.clear();
        }
    }

    public void setGenOutpDir(@Nullable File file) {

        if (file != null && file.isDirectory()) {

            genOutpDir = file;
            gendirtext.setText(genOutpDir.getAbsolutePath());

        } else {

            genOutpDir = null;
            gendirtext.clear();
        }
    }

    public void addFilesToSign(Collection<File> files) {

        fileList.getItems().addAll(files);
    }

    public void addFilesToGen(Collection<File> files) {

        GenList.getItems().addAll(files);
    }

    public void parseCertificate(File certFile) {
        try {

            this.cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certFile));
            cert.checkValidity();
            certCheck.setSelected(true);

        } catch (CertificateException | IOException e) {

            new Alert(Alert.AlertType.ERROR, "Failed to parse Certificate").showAndWait();
            e.printStackTrace();
            certCheck.setSelected(false);
            this.cert = null;
        }
    }

    public void parseKey(File keyFile) {
        try {

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile.toPath()));
            this.key = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(spec);
            keyCheck.setSelected(true);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {

            new Alert(Alert.AlertType.ERROR, "failed to parse Key").showAndWait();
            e.printStackTrace();
            keyCheck.setSelected(false);
            this.key = null;
        }
    }

    public void parseTreeJSON(File treeFile) {

        try {
            genTree = Merkle.fromJSON(Files.readString(treeFile.toPath()));
            treeCheck.setSelected(true);

        } catch (IOException e) {

            new Alert(Alert.AlertType.ERROR, "failed to parse Tree").showAndWait();
            e.printStackTrace();
            treeCheck.setSelected(false);
            this.genTree = null;
        }
    }
}
