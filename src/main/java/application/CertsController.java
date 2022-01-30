package application;

import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.util.Pair;

import java.io.*;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CertsController {

    private KeyStore ks;
    @FXML private ListView<String> keylist;
    @FXML private TextArea ksText;

    private static final Pattern special = Pattern.compile("[^a-z0-9 ]", Pattern.CASE_INSENSITIVE);
    private static final Pattern uppercase = Pattern.compile("[A-Z]");
    private static final Pattern lowercase = Pattern.compile("[a-z]");
    private static final Pattern num = Pattern.compile("[0-9]");

    public Button cancel, save;
    @FXML private Button addBut, delBut;

    public void initialize() throws KeyStoreException, NoSuchAlgorithmException, CertificateException {

        ks = KeyStore.getInstance("PKCS12");
        boolean retry;
        do {
            retry = false;
            try {
                ks.load(new FileInputStream("keystore.jsk"), Main.enterPW());

            } catch (FileNotFoundException e) {

                try {
                    ks.load(null, Objects.requireNonNull(enternewPW()));

                } catch (NullPointerException | IOException n) {

                    new Alert(Alert.AlertType.ERROR, "Couldn't create Keystore").showAndWait();
                    return;
                }

            } catch (IOException e) {

                Optional<ButtonType> conf = new Alert(Alert.AlertType.CONFIRMATION, "Entered Invalid Password, retry?").showAndWait();
                if (conf.isPresent() && conf.get() == ButtonType.OK) {
                    retry = true;
                }
            }
        } while (retry);

        keylist.getItems().addAll(Collections.list(ks.aliases()));

        keylist.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            try {

                if(ks.containsAlias(newValue)) {

                    ksText.setText(ks.getCertificateChain(newValue)[0].toString());
                    delBut.setDisable(false);

                } else {

                    ksText.clear();
                    delBut.setDisable(true);
                }

            } catch (KeyStoreException e) {

                new Alert(Alert.AlertType.ERROR, "Failed to load Data").showAndWait();
                e.printStackTrace();
                ksText.clear();
            }
        });

        delBut.setOnAction(event -> deletekeypairs(keylist.getSelectionModel().getSelectedItems()));
        addBut.setOnAction(event -> addkeypair());
        save.setOnAction(event -> savekeystore());
    }

    private void savekeystore() {
        try(FileOutputStream stream = new FileOutputStream("keystore.jsk")) {


            ks.store(stream, Main.enterPW());

        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {

            new Alert(Alert.AlertType.ERROR, "Couldn't store key data").showAndWait();
            e.printStackTrace();
        }
    }

    private void deletekeypairs(List<String> items) {
        try {
            for (String item : items) {
                try {
                    ks.deleteEntry(item);
                    keylist.getItems().remove(item);

                } catch (KeyStoreException e) {

                    new Alert(Alert.AlertType.ERROR, "Failed to delete entry" + item).showAndWait();
                    e.printStackTrace();
                }
            }
        } catch (IndexOutOfBoundsException | NullPointerException e) {

            System.err.println("delete exception that doesn't impact functionality >.>");
        }
    }

    private void addkeypair() {

        Dialog<Pair<String, File[]>> d = new Dialog<>();
        d.setTitle("Add Keypair");
        d.setHeaderText("Please select Key and Certificate files");
        d.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);

        Button keySel = new Button("Select Key File...");
        Button certSel = new Button("Select Certificate File...");
        Label label = new Label("Both files must be in .der format!");
        TextField alias = new TextField();
        alias.setPromptText("Set Name/Alias for key");

        VBox vBox = new VBox(10);
        HBox hBox = new HBox(10);

        hBox.getChildren().addAll(keySel, certSel);
        vBox.getChildren().addAll(label, alias, hBox);
        vBox.setAlignment(Pos.CENTER);
        d.getDialogPane().setContent(vBox);

        final File[] files = new File[2];
        keySel.setOnAction(event -> files[0] = new FileChooser().showOpenDialog(d.getOwner()));
        certSel.setOnAction(event -> files[1] = new FileChooser().showOpenDialog(d.getOwner()));

        d.setResultConverter(Button -> {
            if (Button == ButtonType.OK && !alias.getText().isEmpty() && files[0] != null && files[1] != null) {
                return new Pair<>(alias.getText(), files);
            }
            return null;
        });

        Optional<Pair<String, File[]>> result = d.showAndWait();
        if (result.isPresent() && result.get().getValue().length == 2) {
            File keyFile = result.get().getValue()[0];
            File certFile = result.get().getValue()[1];
            String name = result.get().getKey();

            try { //Confirm overwrite in case of alias re-use
                if (ks.containsAlias(name)) {
                    Optional<ButtonType> conf =  new Alert(
                            Alert.AlertType.CONFIRMATION,
                            "overwrite keypair named " + name + " ?"
                    ).showAndWait();
                    if (conf.isPresent() && conf.get() == ButtonType.CANCEL) return;
                }

            } catch (KeyStoreException e) {

                System.err.println("Keystore has not been initialized");
                e.printStackTrace();
            }

            try {
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile.toPath()));
                ECPrivateKey eckey = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(spec);

                X509Certificate eccert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certFile));

                ks.setKeyEntry(name, eckey, enternewPW(), new X509Certificate[]{eccert});
                if (!keylist.getItems().contains(ks.getCertificateAlias(eccert))) keylist.getItems().add(ks.getCertificateAlias(eccert));

            } catch (IOException e) {

                new Alert(Alert.AlertType.ERROR, "Could not read file(s)").showAndWait();
                e.printStackTrace();

            } catch (InvalidKeySpecException e) {

                new Alert(Alert.AlertType.ERROR, "Failed to add: Invalid Key").showAndWait();
                e.printStackTrace();

            } catch (KeyStoreException e) {

                new Alert(Alert.AlertType.ERROR, "Failed to save Keypair to Archive").showAndWait();
                e.printStackTrace();

            } catch (NoSuchAlgorithmException | CertificateException e) {

                System.err.println("Fucked up ur algorithms");
                new Alert(Alert.AlertType.ERROR, "Failed to add Keypair (Bug, please report)").showAndWait();
                e.printStackTrace();
            }
        }

    }

    private char[] enternewPW() {
        Dialog<String> d = new Dialog<>();
        d.setTitle("New Password Dialog");
        d.setHeaderText("Password Choice");
        d.setContentText("Please enter your password of choice twice: ");

        PasswordField p1 = new PasswordField();
        PasswordField p2 = new PasswordField();
        VBox box = new VBox(10);
        box.setAlignment(Pos.CENTER_LEFT);
        box.getChildren().addAll(p1, p2);
        d.getDialogPane().setContent(box);

        d.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
        d.setResultConverter(Button -> {
            if (Button == ButtonType.OK) {
                if (!p1.getText().equals(p2.getText())) new Alert(Alert.AlertType.ERROR, "The Passwords do not match").showAndWait();
                else {
                    String password = p1.getText();
                    Matcher m1 = special.matcher(password);
                    Matcher m2 = uppercase.matcher(password);
                    Matcher m3 = lowercase.matcher(password);
                    Matcher m4 = num.matcher(password);
                    if (
                            password.length() < 10
                                    || !m1.find()
                                    || !m2.find()
                                    || !m3.find()
                                    || !m4.find()
                    )
                        new Alert(
                                Alert.AlertType.ERROR,
                                "Your Password must be at least 10 characters long and contain at least an lower- and uppercase letter, a number, and a special character."
                        ).showAndWait();
                    else {
                        return password;
                    }
                }
            }
            return "";
        });
        Optional<String> result = d.showAndWait();
        if (result.isPresent())
            if (result.get().equals("")) return enternewPW();
                else return result.get().toCharArray();
        else return null;
    }
}
