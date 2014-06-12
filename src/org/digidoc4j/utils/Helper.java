package org.digidoc4j.utils;

import java.io.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;

public class Helper {
  public static boolean isZipFile(File file) throws IOException {
    DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(file)));
    int test = in.readInt();
    in.close();
    return test == 0x504b0304;
  }

  public static boolean isXMLFile(File file) throws ParserConfigurationException {
    DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
    try {
      Document doc = dBuilder.parse(file);
    } catch (Exception e) {
      return false;
    }
    return true;
  }
}
