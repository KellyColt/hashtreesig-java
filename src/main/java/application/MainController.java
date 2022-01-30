package application;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import htjsw.HTJSWVerifier;
import htjsw.HTJWSBuilder;
import htjsw.Merkle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.jetbrains.annotations.Nullable;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

/**
 * Controller zwischen Programm und GUI
 * @author F. Krause, SMSB HOST
 */
public class MainController {

    public MenuBar menu;
    public MenuItem full, comp, max, certs, about, delete;
    public Button outpDirBut, closeBut, fileSelBut, verify, gen, genfilesel, treesel, genoutp, verSel;

    @FXML private ChoiceBox<String> keyChoice;

    private File outpDir,  genOutpDir;
    @FXML private TextField outpDirShow, gendirtext;
    @FXML private TextArea sigshow;
    @FXML private Label verifyout;

    @FXML private ListView<File> fileList, GenList;

    @FXML private CheckBox treeCheck, sigcheck;

    @FXML private Button signBut;
    @FXML private ProgressBar sigProg, genbar;

    private Merkle genTree;
    private JWSObject jws;
    private KeyStore ks;

    public void initialize() {

        delete.setOnAction(event -> {
            Optional<ButtonType> conf = new Alert(
                    Alert.AlertType.CONFIRMATION,
                    "Do you wish completely delete your current Key Archive? You will not be able to restore it."
            ).showAndWait();
            if (conf.isPresent() && conf.get() == ButtonType.OK) {

                try {
                    Files.delete(new File("keystore.jsk").toPath());

                } catch (IOException e) {

                    new Alert(Alert.AlertType.ERROR, "Could not properly delete KeyStore, please try manually deleting the file in the program folder").showAndWait();
                    e.printStackTrace();
                }
            }
        });

        String abttxt = "";
        try {
            abttxt = Files.readString(Paths.get(getClass().getResource("/about.txt").toURI()));

        } catch (IOException | URISyntaxException e) {

            System.err.println("about text gone");
        }

        String finalAbttxt = abttxt;
        about.setOnAction(event -> new Alert(Alert.AlertType.INFORMATION, finalAbttxt).showAndWait());

        boolean retry;
        do{
            retry = false;
            try{
                ks = KeyStore.getInstance("PKCS12");
                ks.load(new FileInputStream("keystore.jsk"), Main.enterPW());

                keyChoice.getItems().addAll(Collections.list(ks.aliases()));
                if (keyChoice.getItems().size() > 0) keyChoice.setDisable(false);

            } catch (KeyStoreException e) {

                System.err.println("U messed up ur Keystore Instantiation");
                e.printStackTrace();

            } catch (FileNotFoundException ignored) {

            } catch ( NoSuchAlgorithmException | CertificateException e){

                new Alert(Alert.AlertType.ERROR, "Failed to load Keystore").showAndWait();
                e.printStackTrace();

            } catch (IOException e) {

                Optional<ButtonType> conf = new Alert(Alert.AlertType.CONFIRMATION, "Entered Invalid Password, retry?").showAndWait();
                if (conf.isPresent() && conf.get() == ButtonType.OK) {
                    retry = true;
                }
            }
        } while(retry);

        signBut.setOnAction(this::sign);
        gen.setOnAction(this::generate);
        verify.setOnAction(this::verify);
    }

    private void sign(ActionEvent actionEvent) {
        sigProg.setProgress(-1);

        if (keyChoice.getSelectionModel().getSelectedItem().isEmpty()) {
            new Alert(Alert.AlertType.ERROR, "No valid key pair has been selected!").showAndWait();
            sigProg.setProgress(0);
            return;
        }

        try {
            boolean retry;

            do {
                retry = false;

                try {
                    Merkle merkle = new Merkle((ECPrivateKey) ks.getKey(keyChoice.getValue(), Main.enterPW()), (X509Certificate) ks.getCertificateChain(keyChoice.getValue())[0]);

                    sigProg.setProgress(0);
                    for (File file : fileList.getItems()) {

                        merkle.add(Files.readAllBytes(file.toPath()));
                        sigProg.setProgress((1.0 / fileList.getItems().size()) * 0.5);
                    }

                    merkle.closeAndSign();
                    sigProg.setProgress(0.75);

                    new FileOutputStream(new File(outpDir, "tree-%d.json".formatted(System.currentTimeMillis())))
                            .write(merkle.serialize().getBytes(StandardCharsets.UTF_8));

                } catch (UnrecoverableKeyException e) {

                    Optional<ButtonType> conf = new Alert(Alert.AlertType.CONFIRMATION, "Entered Invalid Password, retry?").showAndWait();
                    if (conf.isPresent() && conf.get() == ButtonType.OK) {
                        retry = true;
                    }
                }

            } while(retry);

            sigProg.setProgress(1);
            new Alert(Alert.AlertType.INFORMATION, "Successfully generated signed Hashtree!");

        } catch (NoSuchAlgorithmException e) {

            e.printStackTrace();
            sigProg.setDisable(true);

        } catch (IOException e) {

            new Alert(Alert.AlertType.ERROR, "Failed to read or write file").showAndWait();
            e.printStackTrace();
            sigProg.setProgress(0);

        } catch (KeyStoreException e) {

            new Alert(Alert.AlertType.ERROR, "Could not use the selected Keypair").showAndWait();
            e.printStackTrace();
            sigProg.setProgress(0);
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
        new Alert(Alert.AlertType.INFORMATION, "Signature Generation successful!");
    }

    private void verify(ActionEvent actionEvent) {

        try {

            if (jws.verify(new HTJSWVerifier())) verifyout.setText("Verification Successful!");
            else verifyout.setText("Verification Failed! Signature invalid!");

        } catch ( JOSEException e) {

            new Alert(Alert.AlertType.ERROR, "failed to perform verification").showAndWait();
            verifyout.setText("Failed to perform Verification");

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
