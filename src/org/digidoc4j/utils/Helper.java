package org.digidoc4j.utils;

import java.io.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class Helper {
  public static boolean isZipFile(File file) throws IOException {
    DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(file)));
    int test = in.readInt();
    in.close();
    return test == 0x504b0304;
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
}
