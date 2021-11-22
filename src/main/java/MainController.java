import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.jetbrains.annotations.Nullable;

import java.io.File;

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
    public Button outpDirBut, closeBut;

    private File outpDir;
    @FXML private TextField outpDirShow;

    public void initialize() {

    }

    public void setOutpDir(@Nullable File file) {
        if (file != null && file.isDirectory()) {
            outpDir = file;
            outpDirShow.setText(outpDir.getAbsolutePath());
        }
    }
}
