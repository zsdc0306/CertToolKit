package com.cert;

import java.io.File;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.example.FileHelper;
import org.ejbca.cvc.*;
import org.json.*;
import java.util.Date;
import java.util.Base64;
import java.util.Spliterator;

import org.apache.commons.cli.*;



public class Main {
    private Options addOption(String[] args){
        Options options = new Options();
        Option deserializeCVC = new Option("l", "load", true, "read cvc file");
        Option serializeCVC = new Option("d","serialize", true,"cvc data byte");
        Option generateCVC = new Option("g", "generate", true, "generate the certificate");
        Option getByte = new Option("e", "getbyte", true, "get byte from file name");
        options.addOption(deserializeCVC);
        options.addOption(serializeCVC);
        options.addOption(generateCVC);
        options.addOption(getByte);
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

    private void extractCert(byte[] certData){
        try {
            CVCertificate cvc = CertificateParser.parseCertificate(certData);
            String cert_id = cvc.getCertificateBody().getAuthorityReference().getMnemonic();
            Date today = new Date();
            boolean valid_to = cvc.getCertificateBody().getValidTo().after(today);
            byte[] pk = cvc.getCertificateBody().getPublicKey().getEncoded();
            System.out.println(cert_id+","+valid_to+","+Base64.getEncoder().encodeToString(pk));
        }
        catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    private void getCertIDAndStatus(String recvStr){
        extractCert(decodeCertStr(recvStr));
    }


    private void getEncodedByte(String file){
        try{
            byte[] certbyte = getByteFromCertFile(file);
            String encodedCertStr = Base64.getEncoder().encodeToString(certbyte);
            System.out.println(encodedCertStr);
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
    }


    private byte[] decodeCertStr(String str){
        return Base64.getDecoder().decode(str);
    }


    private byte[] getByteFromCertFile(String file){
        try {
            return FileHelper.loadFile(file);
        }catch (Exception e){
            System.out.println(e.getMessage());
            return null;
        }
    }


    public static void main(String[] args) {
        Main app = new Main();
        Options options = app.addOption(args);
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;
        try{
            cmd = parser.parse(options, args);
        }catch(ParseException e){
            System.out.println(e.getMessage());
            formatter.printHelp("cert path", options);
            System.exit(1);
            return;
        }
        if(cmd.hasOption("l")){
            try {
                String file = cmd.getOptionValue("l");
                System.out.println(app.serializeCert(file));
            }
            catch (Exception e){
                System.out.println(e.getMessage());
            }

        }
        if(cmd.hasOption("e")){
            String file = cmd.getOptionValue("e");
            System.out.println(file);
            app.getEncodedByte(file);
        }
        if(cmd.hasOption("g")){
            String str = "fyGCAWx/ToHkXykBAEIQVVNQQVNTLUNWQ0EwMDAwMX9JgZQGCgQAfwAHAgICAQGBgYC5sSuW+3Ovydqb1AxgaBozq+WilQZrB9xqdzzaEQASg90+zBhU8yAp661/2lBbk44YlEEVy44371OLU9Nk4u+BPsIql/j0dfPV+tqDSUqDu6oUZ3kPtjpPHl4JAl2Q4TKCaDWbh04P+HHEb+ebeSxaqgvwtr/amhzmY5bNuckBmYIDAQABXyAQVVNQQVNTLUNWQ0EwMDAwMX9MDgYJBAB/AAcDAQIBUwEDXyUGAQcBAQEFXyQGAQgAAgEFXzeBgFVe4fkm1QzqHa9iJ3q1rMAttigaQgGb01f35+Qg1QE0YJdzyVEao2ffN989M6kWHRYv7IJxLx5d49dqEYfQhR7ueyQmJ9nNExTDqpJmmi/wsFGG8TpPCnTfgOYU7M+Yii4VoEqrkA5MgysDYQFrw4dan9dtZ85bLD93qGVQA1wC";
//            String str = cmd.getOptionValue("g");
            app.getCertIDAndStatus(str);
        }


    }
}
