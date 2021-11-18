import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.util.Objects;

// @TODO define output
/**
 * vllt einen gesamt-signatur-file?
 * Main executable, JavaFX application
 * @author F. Krause, SMSB HOST
 */
public class Main extends Application {

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
        Parent root = FXMLLoader.load(Objects.requireNonNull(Main.class.getResource("scene.fxml")));

        Scene scene = new Scene(root);
        //scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("main.css")).toExternalForm());

        primaryStage.setTitle("JavaFX and Gradle");
        primaryStage.setScene(scene);
        primaryStage.show();
    }
}
