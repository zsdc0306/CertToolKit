package com.cert;

import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.example.FileHelper;
import org.ejbca.cvc.*;
import java.util.Date;
import java.util.Base64;

import org.apache.commons.cli.*;



public class Main {
    private Options addOption(String[] args){
        Options options = new Options();
        Option help = new Option("h", "help",false,"print this information");
        Option loadCVC = Option.builder("l")
                .longOpt("load")
                .argName("file path")
                .hasArg()
                .desc("read cvc file to text")
                .build();
        Option decodeCVC = Option.builder("d")
                .longOpt("decode")
                .hasArg()
                .argName("file path")
                .desc("get decoded CVC text")
                .build();
        Option extractCVC = Option.builder("e")
                .longOpt("extract")
                .hasArg()
                .argName("file path")
                .desc("encoded CVC")
                .build();
        Option checkCVC = Option.builder("c")
                .longOpt("check")
                .hasArg()
                .argName("Encoded cert")
                .desc("check cert id, status and public key")
                .build();
        Option generateCVC = new Option("g", "generate", true, "generate the certificate");
        options.addOption(help);
        options.addOption(loadCVC);
        options.addOption(decodeCVC);
        options.addOption(generateCVC);
        options.addOption(extractCVC);
        options.addOption(checkCVC);
        return options;
    }

    private String readCert(String file) {
        String cert;
        try {
            byte[] certData = getByteFromCertFile(file);
            if(certData != null) {
                CVCertificate cvc = CertificateParser.parseCertificate(certData);
                cert=cvc.getAsText(); // NOPMD
                return cert;
            }else{
                return "";
            }
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return "";
    }

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

    private void decodeCert(String str){
        byte[] certdata = decodeCertStr(str);
        try{
            CVCertificate cvc = CertificateParser.parseCertificate(certdata);
            System.out.println(cvc.getAsText());
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    private void getEncodeStr(String file){
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


    private byte[] getByteFromCertFile(String filePath){
        try {
            return FileHelper.loadFile(filePath);
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
            formatter.printHelp("CVC cert toolkit", options);
            System.exit(1);
            return;
        }
        if(cmd.hasOption("h")){
            formatter.printHelp("CVC cert toolkit", options);
            System.exit(1);
        }

        if(cmd.hasOption("l")){
            try {
                String file = cmd.getOptionValue("l");
                System.out.println(app.readCert(file));
            }
            catch (Exception e){
                System.out.println(e.getMessage());
            }
        }
        if(cmd.hasOption("d")){
            try {
                String str = cmd.getOptionValue("d");
                app.decodeCert(str);
            }
            catch (Exception e){
                System.out.println(e.getMessage());
            }
        }
        if(cmd.hasOption("e")){
            String file = cmd.getOptionValue("e");
            app.getEncodeStr(file);
        }
        if(cmd.hasOption("c")){
//            String str = "fyGCAWx/ToHkXykBAEIQVVNQQVNTLUNWQ0EwMDAwMX9JgZQGCgQAfwAHAgICAQGBgYC5sSuW+3Ovydqb1AxgaBozq+WilQZrB9xqdzzaEQASg90+zBhU8yAp661/2lBbk44YlEEVy44371OLU9Nk4u+BPsIql/j0dfPV+tqDSUqDu6oUZ3kPtjpPHl4JAl2Q4TKCaDWbh04P+HHEb+ebeSxaqgvwtr/amhzmY5bNuckBmYIDAQABXyAQVVNQQVNTLUNWQ0EwMDAwMX9MDgYJBAB/AAcDAQIBUwEDXyUGAQcBAQEFXyQGAQgAAgEFXzeBgFVe4fkm1QzqHa9iJ3q1rMAttigaQgGb01f35+Qg1QE0YJdzyVEao2ffN989M6kWHRYv7IJxLx5d49dqEYfQhR7ueyQmJ9nNExTDqpJmmi/wsFGG8TpPCnTfgOYU7M+Yii4VoEqrkA5MgysDYQFrw4dan9dtZ85bLD93qGVQA1wC";
            String str = cmd.getOptionValue("c");
            app.getCertIDAndStatus(str);
        }
        if(cmd.hasOption("g")){
            System.out.println("not implemented");
        }



    }
}
