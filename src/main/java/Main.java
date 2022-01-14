import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.util.Objects;

// @TODO define output
/**
 * vllt einen gesamt-signatur-file?
 * Main executable, JavaFX application
 * @author F. Krause, SMSB HOST
 */
public class Main extends Application {

    enum WINDOW{
        FULL,
        MAX,
        COMP
    }

    private static double xOffset = 0;
    private static double yOffset = 0;

    /**
     * main executable, launches GUI
     * @param args parameters
     */
    public static void main(String[] args) {
        System.out.println("Hello World!");
        launch();
    }

    /**
     * JavaFX start class for loading GUI
     * @param primaryStage initial stage
     * @throws Exception Nullpointer or IO if ressource failed to load, IllegalState if threads got messed up
     */
    @Override
    public void start(Stage primaryStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(Objects.requireNonNull(this.getClass().getResource("scene.fxml")));
        Parent root = loader.load();
        MainController cont = loader.getController();

        Scene scene = new Scene(root);
        //scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("main.css")).toExternalForm());

        primaryStage.setTitle("Merkle Hashtree Signature Application");
        primaryStage.initStyle(StageStyle.TRANSPARENT);
        primaryStage.setScene(scene);
        primaryStage.show();

        cont.menu.setOnMousePressed(event -> {
            xOffset = primaryStage.getX() - event.getScreenX();
            yOffset = primaryStage.getY() - event.getScreenY();
        });
        cont.menu.setOnMouseDragged(event -> {
            primaryStage.setX(event.getScreenX() + xOffset);
            primaryStage.setY(event.getScreenY() + yOffset);
        });

        cont.closeBut.setOnAction(event -> primaryStage.close());

        cont.full.setOnAction(event -> setWindow(primaryStage, WINDOW.FULL));
        cont.max.setOnAction(event -> setWindow(primaryStage, WINDOW.MAX));
        cont.comp.setOnAction(event -> setWindow(primaryStage, WINDOW.COMP));

        cont.outpDirBut.setOnAction(event -> cont.setOutpDir(new DirectoryChooser().showDialog(primaryStage)));
        cont.genoutp.setOnAction(event -> cont.setGenOutpDir(new DirectoryChooser().showDialog(primaryStage)));

        cont.fileSelBut.setOnAction(event -> cont.addFilesToSign(new FileChooser().showOpenMultipleDialog(primaryStage)));
        cont.genfilesel.setOnAction(event -> cont.addFilesToGen(new FileChooser().showOpenMultipleDialog(primaryStage)));

        cont.keySelBut.setOnAction(event -> cont.parseKey(new FileChooser().showOpenDialog(primaryStage)));
        cont.certSelBut.setOnAction(event -> cont.parseCertificate(new FileChooser().showOpenDialog(primaryStage)));
        cont.treesel.setOnAction(event -> cont.parseTreeJSON(new FileChooser().showOpenDialog(primaryStage)));
        cont.verSel.setOnAction(event -> cont.parseJWS(new FileChooser().showOpenDialog(primaryStage)));

    }

    private void setWindow(Stage stage, WINDOW w) {
        stage.setFullScreen(w == WINDOW.FULL);
        stage.setMaximized(w == WINDOW.MAX);
    }
}
