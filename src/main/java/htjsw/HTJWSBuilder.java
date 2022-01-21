package htjsw;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

import java.text.ParseException;

/**
 * method collection for extracting JWSs from MerkleHashTrees
 * @author F. Krause, 17575 SMSB HOST
 */
public abstract class HTJWSBuilder {

    /**
     * builds JWSobject for given message
     * @param merkTree htjsw.Merkle Tree Structure that is closed and signed, containing msg
     * @param msg message to generate JWS for
     * @return JSON Web Signature of this message
     * @throws Merkle.ConcatException if somewhere along the way the concatenation glitches
     * @throws ParseException if a part of the JWS fails to generate properly
     * @throws IllegalArgumentException if the given msg is not contained in the given Tree
     */
    public static JWSObject genJWS(Merkle merkTree, byte[] msg) throws Merkle.ConcatException, ParseException, IllegalArgumentException {

        return new JWSObject(
                Base64URL.encode(
                        genHeaderJSON(merkTree).toString()
                ),
                new Payload(msg),
                Base64URL.encode(
                        genSigJSON(merkTree, msg).toString()
                )
        );
    }

    /**
     * generates JWS Header with Algorithm and Certificate data
     * @param merkTree htjsw.Merkle Hashtree Structure that has been initialised with a Certificate
     * @return resulting JSON Object
     * @throws IllegalStateException if the given structure has not been initialised with a Certificate
     */
    public static JSONObject genHeaderJSON(@NotNull Merkle merkTree) throws IllegalStateException {
        if (merkTree.getStatus() == -1 || merkTree.cert == null)
            throw new IllegalStateException("No Certificate has been initialised");

        return new JSONObject()
                .put("alg", "HTES256")
                .put(
                        "x5c",
                        new String[]{ merkTree.cert.toString() }
                );
    }

    /**
     * generates the third part (signature) of the JWS for the given message
     * @param merkTree Hashtree Structure containing the Message, must be closed and signed
     * @param msg message to search and generate for
     * @return resulting JSON Object containing ht_path and ecdsa_sig over root
     * @throws Merkle.ConcatException if concatenation glitches
     * @throws IllegalStateException if the given Hashtree is not closed and signed
     * @throws IllegalArgumentException if the given message is not contained in this hashtree
     */
    public static JSONObject genSigJSON(Merkle merkTree, byte[] msg) throws Merkle.ConcatException, IllegalStateException, IllegalArgumentException {
        if (merkTree.getSignature() == null) throw new IllegalStateException("Tree is not properly signed");

        return new JSONObject()
                .put("ht_path", merkTree.getPath(msg))
                .put("ecdsa_sig", merkTree.getSignature().toString());
    }
}
