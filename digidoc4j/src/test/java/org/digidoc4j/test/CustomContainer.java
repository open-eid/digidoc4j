/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.NotYetImplementedException;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * This class is used in unit tests for testing custom container creation.
 */
public class CustomContainer implements Container {

  private Configuration configuration;
  private String openedFromFile;
  private InputStream openedFromStream;

  public static String type = "TEST-FORMAT";

  public CustomContainer() {
  }

  public CustomContainer(Configuration configuration) {
    this.configuration = configuration;
  }

  public CustomContainer(String filePath) {
    this.openedFromFile = filePath;
  }

  public CustomContainer(String filePath, Configuration configuration) {
    this.openedFromFile = filePath;
    this.configuration = configuration;
  }

  public CustomContainer(InputStream openedFromStream) {
    this.openedFromStream = openedFromStream;
  }

  public CustomContainer(InputStream openedFromStream, Configuration configuration) {
    this.openedFromStream = openedFromStream;
    this.configuration = configuration;
  }

  @Override
  public String getType() {
    return type;
  }

  public static void resetType() {
    type = "TEST-FORMAT";
  }

  public Configuration getConfiguration() {
    return configuration;
  }

  public String getOpenedFromFile() {
    return openedFromFile;
  }

  public InputStream getOpenedFromStream() {
    return openedFromStream;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    return null;
  }

  @Override
  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    return null;
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    return null;
  }

  @Override
  public void addDataFile(DataFile dataFile) {
  }

  @Override
  public void addSignature(Signature signature) {

  }

  @Override
  public List<DataFile> getDataFiles() {
    return null;
  }

  @Override
  public List<Signature> getSignatures() {
    return null;
  }

  @Override
  public void removeDataFile(DataFile file) {

  }

  @Override
  public void removeSignature(Signature signature) {

  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {

  }

  @Override
  public File saveAsFile(String filePath) {
    return null;
  }

  @Override
  public InputStream saveAsStream() {
    return null;
  }

  @Override
  public ContainerValidationResult validate() {
    return null;
  }

  @Override
  public void setTimeStampToken(DataFile timeStampToken) {
    throw new NotYetImplementedException();
  }

  @Override
  public DataFile getTimeStampToken() {
    throw new NotYetImplementedException();
  }

  @Override
  public void save(OutputStream out) {

  }

}
