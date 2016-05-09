/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.utils;

import static eu.europa.esig.dss.MimeType.ASICE;
import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;
import static org.digidoc4j.utils.Helper.deleteFile;
import static org.digidoc4j.utils.Helper.deserializer;
import static org.digidoc4j.utils.Helper.serialize;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.junit.AfterClass;
import org.junit.Test;

public class HelperTest {
  @AfterClass
  public static void cleanup() throws IOException {
    deleteFile("extractSignatureThrowsErrorWhenSignatureIsNotFound.zip");
  }

  @Test
  public void testIsXMLFileWhenFileIsNotXMLFile() throws Exception {
    assertFalse(Helper.isXMLFile(new File("testFiles/test.txt")));
  }

  @Test
  public void testIsXMLFileWhenFileIsXMLFile() throws Exception {
    createXMLFile("testIsXMLFileWhenFileIsXMLFile.xml");
    assertTrue(Helper.isXMLFile(new File("testIsXMLFileWhenFileIsXMLFile.xml")));
    deleteFile("testIsXMLFileWhenFileIsXMLFile.xml");
  }

  private void createXMLFile(String fileName) throws IOException {
    FileWriter writer = new FileWriter(fileName);
    writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><test></test>");
    writer.flush();
    writer.close();
  }

  @Test
  public void testIsZIPFileWhenFileIsNotZIPFile() throws Exception {
    assertFalse(Helper.isZipFile(new File("testFiles/test.txt")));
  }

  @Test
  public void testIsZIPFileWhenFileIsZIPFile() throws Exception {
    FileOutputStream fileOutputStream = new FileOutputStream("test.zip");
    ZipOutputStream zipOutputStream = new ZipOutputStream(fileOutputStream);
    zipOutputStream.putNextEntry(new ZipEntry("testFiles/test.txt"));
    zipOutputStream.closeEntry();

    assertTrue(Helper.isZipFile(new File("test.zip")));

    fileOutputStream.close();

    deleteFile("test.zip");
  }

  @Test
  public void testDeleteFileIfExists() throws Exception {
    File file = new File("testDelete.txt");
    //noinspection ResultOfMethodCallIgnored
    file.createNewFile();

    assertTrue(file.exists());
    deleteFile("testDelete.txt");
    assertFalse(file.exists());
  }

  @Test
  public void testDeleteFileIfNotExists() throws Exception {
    deleteFile("testDeleteNotExists.txt");
    assertFalse(new File("testDeleteNotExists.txt").exists());
  }

  @Test
  public void extractSignatureS0() throws Exception {
    createZIPFile();
    assertEquals("A", Helper.extractSignature("extractSignature.zip", 0));

    deleteFile("extractSignature.zip");
  }

  @Test
  public void extractSignatureS1() throws Exception {
    createZIPFile();
    assertEquals("B", Helper.extractSignature("extractSignature.zip", 1));

    deleteFile("extractSignature.zip");
  }

  @Test(expected = IOException.class)
  public void extractSignatureThrowsErrorWhenSignatureIsNotFound() throws Exception {
    try (
        FileOutputStream fileOutputStream = new FileOutputStream("extractSignatureThrowsErrorWhenSignatureIsNotFound.zip");
        ZipOutputStream zipOutputStream = new ZipOutputStream(fileOutputStream)) {

      ZipEntry zipEntry = new ZipEntry("test");
      zipOutputStream.putNextEntry(zipEntry);

      zipOutputStream.write(0x42);
      zipOutputStream.closeEntry();
    }

    Helper.extractSignature("extractSignatureThrowsErrorWhenSignatureIsNotFound.zip", 0);
  }

  private void createZIPFile() throws IOException {
    try(FileOutputStream out = new FileOutputStream("extractSignature.zip");
        ZipOutputStream zout = new ZipOutputStream(out)) {
      ZipEntry signature0 = new ZipEntry("META-INF/signatures0.xml");
      zout.putNextEntry(signature0);
      zout.write(0x41);
      zout.closeEntry();

      ZipEntry signature1 = new ZipEntry("META-INF/signatures1.xml");
      zout.putNextEntry(signature1);
      zout.write(0x42);
      zout.closeEntry();
    }
  }

  @Test
  public void createUserAgentForBDOC() throws Exception {
    String userAgent = Helper.createBDocUserAgent();
    assertThat(userAgent, containsString(ASICE.getMimeTypeString()));
  }

  @Test
  public void createUserAgentForDDOC() throws Exception {
    String userAgent = Helper.createUserAgent(ContainerBuilder.aContainer(DDOC_CONTAINER_TYPE).build());
    assertThat(userAgent, containsString("DDOC"));
  }

  @Test
  public void  createUserAgentSignatureProfileForBDOC() {
    String userAgent = Helper.createBDocUserAgent(SignatureProfile.LTA);
    assertThat(userAgent, containsString("signatureProfile: ASiC_E_BASELINE_LTA"));
  }

  @Test
  public void createUserAgentForUnknownSignatureProfile() {
    String userAgent = Helper.createBDocUserAgent();
    assertThat(userAgent, containsString("signatureProfile: ASiC_E"));
  }

  @Test
  public void createUserAgentSignatureProfileForBDocTm() throws Exception {
    String userAgent = Helper.createBDocUserAgent(SignatureProfile.LT_TM);
    assertThat(userAgent, containsString("signatureProfile: ASiC_E_BASELINE_LT_TM"));
  }

  @Test
  public void createUserAgentSignatureProfileForBDocTs() throws Exception {
    String userAgent = Helper.createBDocUserAgent(SignatureProfile.LT);
    assertThat(userAgent, containsString("signatureProfile: ASiC_E_BASELINE_LT"));
  }

  @Test
  public void  createUserAgentSignatureProfileForDDOC() {
    Container container = ContainerBuilder.aContainer(DDOC_CONTAINER_TYPE).build();
    String userAgent = Helper.createUserAgent(container);
    assertThat(userAgent, containsString("signatureProfile: LT_TM"));
  }

  @Test
  public void  createUserAgentSignatureVersionForDDOC() {
    Container container = ContainerBuilder.aContainer(DDOC_CONTAINER_TYPE).build();
    String userAgent = Helper.createUserAgent(container);
    assertThat(userAgent, containsString("format: DDOC/1.3"));
  }

  @Test
  public void  createUserAgentSignatureVersionForBDOC() {
    String userAgent = Helper.createBDocUserAgent();
    assertThat(userAgent, containsString("format: application/vnd.etsi.asic-e+zip"));
  }

  @Test (expected = DigiDoc4JException.class)
  public void deserializeThrowsException() {
    deserializer(null);
  }

  @Test (expected = DigiDoc4JException.class)
  public void serializeThrowsException() {
    serialize(ContainerBuilder.aContainer().build(), null);
  }


}
