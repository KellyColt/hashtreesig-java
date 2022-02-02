package application;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.io.IOException;
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
 * Main executable and universal function library, JavaFX application
 * @author F. Krause
 */
public class Main extends Application {

    /**
     * enum for window size
     */
    enum WINDOW{

        /**
         * fullscreen
         */
        FULL,

        /**
         * maximised
         */
        MAX,

        /**
         * windowed small
         */
        COMP
    }

    /**
     * numeric mouse position variable for dynamic window resizing
     */
    private static double xOffset = 0, yOffset = 0;

    /**
     * main executable, launches GUI
     * @param args parameters
     */
    public static void main(String[] args) {
        launch();
    }

    /**
     * JavaFX start class for loading GUI
     * @param primaryStage initial stage
     * @throws Exception Nullpointer or IO if ressource failed to load, IllegalState if threads got messed up
     */
    @Override
    public void start(Stage primaryStage) throws Exception {

        FXMLLoader loader = new FXMLLoader(Objects.requireNonNull(this.getClass().getResource("/scene.fxml")));
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

        cont.treesel.setOnAction(event -> cont.parseTreeJSON(new FileChooser().showOpenDialog(primaryStage)));
        cont.verSel.setOnAction(event -> cont.parseJWS(new FileChooser().showOpenDialog(primaryStage)));
    }

    /**
     * for setting universal window sizes using menu
     * @param stage the window
     * @param w window enum value
     */
    private void setWindow(Stage stage, WINDOW w) {

        stage.setFullScreen(w == WINDOW.FULL);
        stage.setMaximized(w == WINDOW.MAX);
    }


    /**
     * universal function for opening a Password check dialogue
     * @return entered Password as a char array
     */
    public static char[] enterPW() {

        Dialog<String> d = new Dialog<>();
        d.setTitle("Password Dialog");
        d.setHeaderText("Password Check");

        PasswordField pass = new PasswordField();
        Label cont = new Label("Please Enter your Password:");
        VBox box = new VBox(10);
        box.setAlignment(Pos.CENTER);
        box.getChildren().addAll(cont, pass);
        d.getDialogPane().setContent(box);

        d.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
        d.setResultConverter(Button -> {
            if (Button == ButtonType.OK) {
                return pass.getText();
            }
            return "";
        });

        Optional<String> result = d.showAndWait();
        if(result.isPresent()) return(result.get().toCharArray());

        else return "".toCharArray();
    }
}
