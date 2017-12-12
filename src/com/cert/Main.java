package com.cert;

import java.io.File;
import java.security.cert.CertificateFactory;

import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.example.FileHelper;
import org.ejbca.cvc.*;
import org.json.*;
import org.apache.commons.cli.*;
import java.util.Date;


public class Main {
    private Options addOption(String[] args){
        Options options = new Options();
        Option deserializeCVC = new Option("s", "deserialize", true, "cvc file path");
        Option serializeCVC = new Option("d","serialize", true,"cvc data string");
        Option generateCVC = new Option("g", "generate", true, "generate the certificate");
        options.addOption(deserializeCVC);
        options.addOption(serializeCVC);
        options.addOption(generateCVC);
        return options;
    }

    private String serializeCert(String file) {
        String cert;
        try {
            byte[] certData = FileHelper.loadFile(file);
            CVCertificate cvc = CertificateParser.parseCertificate(certData);
            String cert_id = cvc.getCertificateBody().getAuthorityReference().getMnemonic();
            cert=cvc.getAsText(); // NOPMD
            return cert;
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

//    private static JSONObject toJson(String certStr){
//        JSONObject obj = new JSONObject(certStr);
//        return obj;
//    }

    private String extractID(byte[] certData){
        try {
            CVCertificate cvc = CertificateParser.parseCertificate(certData);
            String cert_id = cvc.getCertificateBody().getAuthorityReference().getMnemonic();
            Boolean valid_to = cvc.getCertificateBody().getValidTo().before(new Date());
            return cert_id;
        }
        catch (Exception e){
            System.out.println(e.getMessage());
            return null;
        }
    }


    public static void main(String[] args) {
        Main app = new Main();
        Options options = app.addOption(args);
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;
        try{
            cmd = parser.parse(options, args);
        }catch(ParseException e){
            System.out.println(e.getMessage());
            formatter.printHelp("cert path", options);
            System.exit(1);
            return;
        }
        if(options.hasOption("s")){
            try {
                String file = cmd.getOptionValue("s");
                System.out.println(app.serializeCert(file));
                return;
            }
            catch (Exception e){
                System.out.println(e.getMessage());
                return;
            }

        }
        if(options.hasOption("d")){
            System.out.println("deserialize not implemented");
        }
        if(options.hasOption("g")){
            System.out.println("generate not implemented");
        }


    }
}
