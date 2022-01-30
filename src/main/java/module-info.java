module hashtreesig.main {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.json;
    requires com.nimbusds.jose.jwt;
    requires org.jetbrains.annotations;
    requires com.fasterxml.jackson.databind;

    exports htjsw;
    exports application;

    opens application;
    opens htjsw;
}