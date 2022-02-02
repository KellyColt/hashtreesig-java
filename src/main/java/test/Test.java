package test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import htjsw.HTJSWVerifier;
import htjsw.HTJWSBuilder;
import htjsw.Merkle;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;

//@TODO test different size trees
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
 * a debugging executable class
 * @author F. Krause, SMSB HOST
 */
public abstract class Test {
    /**
     * number of test leaves to generate
     */
    private static final int test_nr = 3;

    /**
     * runnable
     * @param args parameters
     * @throws JOSEException if verification error occurs
     */
    public static void main(String[] args) throws JOSEException {

        System.out.println("Hello World");

        File certFile = new File("pki/signer_cert.der");
        File keyFile = new File("pki/signing_key.der");

        ArrayList<byte[]> list = new ArrayList<>();
        for (int i = 0; i < test_nr; i++) {

            byte[] msg = ("Hallo, ich bin Nachricht Nr. " + i).getBytes(StandardCharsets.UTF_8);
            list.add(msg);
            System.out.println("Added message " + i);
        }

        byte[] msg = "Hallo, ich bin Nachricht Nr. 2".getBytes(StandardCharsets.UTF_8);

        /* HashTree merkle;
        try {
            merkle = new HashTree(keyFile, certFile);
        } catch (IOException e) {
            System.err.println("Error reading Keyfile");
            e.printStackTrace();
            return;
        } catch (CertificateException e) {
            System.err.println("Error reading Certificate");
            e.printStackTrace();
            return;
        }
        System.out.printf("Ich erzeuge ad-hoc %d Nachrichten %n", test_nr);

        ArrayList<byte[]> list = new ArrayList<>();
        for (int i = 0; i < test_nr; i++) {
            byte[] msg = ("Hallo, ich bin Nachricht Nr. " + i).getBytes(StandardCharsets.UTF_8);
            merkle.add(msg);
            list.add(msg);
            System.out.println("Added message " + i);
        }

        merkle.sign();

        byte[] msg = "Hallo, ich bin Nachricht Nr. 2".getBytes(StandardCharsets.UTF_8);

        JWSObject json_string = merkle.json_web_signature(msg);

        System.out.println(json_string.getHeader().toString());
        System.out.println(json_string.getPayload().toString());
        System.out.println(json_string.getSignature().decodeToString());

        System.out.println(json_string.verify(new htjsw.HTJSWVerifier())); */

        try {
            Merkle merkle2 = new Merkle(keyFile, certFile);
            merkle2.addAll(list);

            merkle2.closeAndSign();

            JWSObject jws2 = HTJWSBuilder.genJWS(merkle2, msg);
            System.out.println(jws2.getHeader().toString());
            System.out.println(jws2.getPayload().toString());
            System.out.println(jws2.getSignature().decodeToString());

            System.out.println(jws2.verify(new HTJSWVerifier(certFile)));

            System.out.println(merkle2.getTreeJSON());
            System.out.println(new ObjectMapper().writeValueAsString(merkle2));
            System.out.println(merkle2.serialize());
            Merkle copy = Merkle.fromJSON(merkle2.serialize());
            //System.out.println(copy.getSignature().toString());

        } catch (NoSuchAlgorithmException e) {
            System.err.println("you mistyped the algorithm dummy");
            e.printStackTrace();
        } catch (ParseException e) {

            System.err.println("couldn't parse certificate (?)");
            e.printStackTrace();

        } catch (Merkle.ConcatException e) {

            System.err.println("Failed to Concat smt");
            e.printStackTrace();
        } catch (CertificateException e) {

            System.err.println("Failed to verify Certificate validity or initiate it at all");
            e.printStackTrace();
        } catch (IOException e) {

            System.err.println("Failed to open Certfile");
            e.printStackTrace();
        } catch (NullPointerException e) {
            e.printStackTrace();
        }
    }
}
