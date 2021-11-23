import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
    public MenuItem full, comp, max;
    public Button outpDirBut, closeBut, fileSelBut, keySelBut, certSelBut;

    private File outpDir;
    @FXML private TextField outpDirShow;

    @FXML private ListView<File> fileList;

    @FXML private CheckBox keyCheck, certCheck;
    private @Nullable X509Certificate cert;
    private @Nullable ECPrivateKey key;

    @FXML private Button signBut;
    @FXML private ProgressBar sigProg;

    public void initialize() {

        signBut.setOnAction(event -> {
            sigProg.setProgress(-1);

            if (!keyCheck.isSelected() || !certCheck.isSelected()) { //@TODO verify if key and cert are a matched pair @TODO implement keystore
                Alert alert = new Alert(Alert.AlertType.ERROR, "No valid key pair has been selected!");
                alert.showAndWait();
                sigProg.setProgress(0);
                return;
            }

            try {

                Merkle merkle = new Merkle(key, cert);

                sigProg.setProgress(0);
                for (File file : fileList.getItems()) {

                    FileInputStream inp = new FileInputStream(file);
                    merkle.add(inp.readAllBytes());
                    sigProg.setProgress((1.0 / fileList.getItems().size()) * 0.5);
                }

                merkle.closeAndSign();
                sigProg.setProgress(0.75);

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
        });
    }

    public void setOutpDir(@Nullable File file) {
        if (file != null && file.isDirectory()) {
            outpDir = file;
            outpDirShow.setText(outpDir.getAbsolutePath());
        }
    }

    public void addFilesToSign(Collection<File> files) {

        fileList.getItems().addAll(files);
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
}
