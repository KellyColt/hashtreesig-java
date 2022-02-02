package application;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import htjsw.HTJSWVerifier;
import htjsw.HTJWSBuilder;
import htjsw.Merkle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
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
import java.util.Objects;
import java.util.Optional;

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
 * Controller zwischen Programm und GUI
 * @author F. Krause
 */
public class MainController {
    /**
     * Menu Bar containing Menus for Keystore, View and Help
     */
    public MenuBar menu;

    /**
     * Menu Item that toggles window resizing process
     */
    public MenuItem full, comp, max;

    /**
     * Menu Item that toggles program internal process
     */
    @FXML private MenuItem certs, about, delete;

    /**
     * Button that toggles File Selection process
     */
    public Button outpDirBut, closeBut, fileSelBut, genfilesel, treesel, genoutp, verSel;

    /**
     * Button that toggles an internal process
     */
    @FXML private Button signBut, gen, verify, clear, genClear;

    /**
     * rolling selector that shows the available keypairs in the keystore
     */
    @FXML private ChoiceBox<String> keyChoice;

    /**
     * variable for output directory
     */
    private File outpDir,  genOutpDir;

    /**
     * shows selected output directory
     */
    @FXML private TextField outpDirShow, gendirtext;

    /**
     * shows certificate extracted from the selected signature
     */
    @FXML private TextArea sigshow;

    /**
     * Label for outputting verification results
     */
    @FXML private Label verifyout;

    /**
     * ListView that shows selected files
     */
    @FXML private ListView<File> fileList, GenList;

    /**
     * used for showing if a (valid) file has been selected
     */
    @FXML private CheckBox treeCheck, sigcheck;

    /**
     * progress bars showing process progress
     */
    @FXML private ProgressBar sigProg, genbar;

    /**
     * Hashtree generated from json file for signature generation
     */
    private Merkle genTree;

    /**
     * variable for holding jws'
     */
    private JWSObject jws;

    /**
     * holds keystore state upon program load
     */
    private KeyStore ks;

    /**
     * called by fxmlloader upon controller initialization
     */
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

        certs.setOnAction(this::openCertsWindow);

        String abttxt = "";

        try {
            abttxt = Files.readString(Paths.get(Objects.requireNonNull(getClass().getResource("/about.txt")).toURI()));

        } catch (IOException | URISyntaxException | NullPointerException e) {

            System.err.println("about text gone");
        }

        String finalAbttxt = abttxt;
        about.setOnAction(event -> new Alert(Alert.AlertType.INFORMATION, finalAbttxt).showAndWait());

        loadKS();

        signBut.setOnAction(this::sign);
        clear.setOnAction(event -> fileList.getItems().clear());

        gen.setOnAction(this::generate);
        genClear.setOnAction(event -> GenList.getItems().clear());

        verify.setOnAction(this::verify);
    }

    /**
     * method that (re)loads the keystore from files
     */
    private void loadKS() {
        boolean retry;

        do {
            retry = false;

            try {

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
    }

    /**
     * executes on menu use, opens utility for managing keystore and pauses main window till done
     * @param actionEvent called by UI Event
     */
    private void openCertsWindow(ActionEvent actionEvent) {

        try {
            FXMLLoader loader = new FXMLLoader(Objects.requireNonNull(this.getClass().getResource("/certs.fxml")));
            Parent root = loader.load();
            CertsController cont = loader.getController();

            Scene scene = new Scene(root);
            Stage certStage = new Stage();
            certStage.setTitle("Merkle Keystore Management");
            certStage.initStyle(StageStyle.UTILITY);
            certStage.setScene(scene);

            cont.cancel.setOnAction(event -> certStage.close());
            certStage.showAndWait();

            loadKS();

        } catch (IOException e) {

            System.err.println("Failed to load utility FXML file");
            e.printStackTrace();
            new Alert(Alert.AlertType.ERROR, "There has been a program error, please try reinstalling").showAndWait();
        }
    }

    /**
     * signing process called by button press.
     * checks if output directory and keypair are selected, asks for password for key use,
     * constructs and signs the hashtree from the files and saves it into the  output directory serialized into json format.
     * progress is output using the  progress bar
     * @param actionEvent called on UI action
     */
    private void sign(ActionEvent actionEvent) {
        sigProg.setProgress(-1);

        if (keyChoice.getSelectionModel().getSelectedItem().isEmpty()) {
            new Alert(Alert.AlertType.ERROR, "No valid key pair has been selected!").showAndWait();
            sigProg.setProgress(0);
            return;
        }

        if (outpDir == null) {
            new Alert(Alert.AlertType.ERROR, "No Output directory has been selected!").showAndWait();
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

    /**
     * signature generation process called by button press.
     * checks if source tree and output directory have been selected,
     * generates JSWs for the selected files one after the other
     * @param actionEvent called on UI action
     */
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

    /**
     * verification process called by button press.
     * checks if signature file has been selected and uses JOSE library functionality and custom verifier class
     * @param actionEvent called on UI action
     */
    private void verify(ActionEvent actionEvent) {

        if(jws == null) {

            new Alert(Alert.AlertType.ERROR, "No Signature is selected").showAndWait();
            return;
        }

        try {

            if (jws.verify(new HTJSWVerifier())) verifyout.setText("Verification Successful!");
            else verifyout.setText("Verification Failed! Signature invalid!");

        } catch ( JOSEException e) {

            new Alert(Alert.AlertType.ERROR, "failed to perform verification").showAndWait();
            verifyout.setText("Failed to perform Verification");

        }
    }

    /**
     * called by application upon JWS file selection
     * @param file file passed from filechooser by main application
     */
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

    /**
     * called by application upon output directory selection
     * @param file file Object passed from directorychooser
     */
    public void setOutpDir(@Nullable File file) {

        if (file != null && file.isDirectory()) {

            outpDir = file;
            outpDirShow.setText(outpDir.getAbsolutePath());

        } else {

            outpDir = null;
            outpDirShow.clear();
        }
    }

    /**
     * called by application upon output directory selection
     * @param file file Object passed from directorychooser
     */
    public void setGenOutpDir(@Nullable File file) {

        if (file != null && file.isDirectory()) {

            genOutpDir = file;
            gendirtext.setText(genOutpDir.getAbsolutePath());

        } else {

            genOutpDir = null;
            gendirtext.clear();
        }
    }

    /**
     * called by the application whenever files are selected to be added to the signing tab file list
     * @param files selected files passed by multiplefilechooser
     */
    public void addFilesToSign(Collection<File> files) {

        fileList.getItems().addAll(files);
    }

    /**
     * called by the application whenever files are selected to be added to the generation tab file list
     * @param files selected files passed by multiplefilechooser
     */
    public void addFilesToGen(Collection<File> files) {

        GenList.getItems().addAll(files);
    }

    /**
     * called by application whenever a tree file is selected to be used in signature generation
     * @param treeFile file passed by filechooser
     */
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
