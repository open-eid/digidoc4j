package org.digidoc4j.utils;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.file.Paths;

import static java.nio.file.Files.deleteIfExists;

public final class Helper {

  private Helper() {

  }

  public static boolean isZipFile(File file) throws IOException {
    DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(file)));
    int test = in.readInt();
    in.close();
    final int zipVerificationCode = 0x504b0304;
    return test == zipVerificationCode;
  }

  public static boolean isXMLFile(File file) throws ParserConfigurationException {
    DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    try {
      builder.parse(file);
    } catch (Exception e) {
      return false;
    }
    return true;
  }

  public static void deleteFile(String file) throws IOException {
    deleteIfExists(Paths.get(file));
  }
}


