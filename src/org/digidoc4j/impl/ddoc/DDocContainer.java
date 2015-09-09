/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.util.List;

import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DDocContainer implements Container {

  private static final Logger logger = LoggerFactory.getLogger(DDocContainer.class);

  private DDocFacade jDigiDocFacade;

  public DDocContainer(DDocFacade jDigiDocFacade) {
    this.jDigiDocFacade = jDigiDocFacade;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    jDigiDocFacade.addDataFile(path, mimeType);
    return new DataFile(path, mimeType);
  }

  @Override
  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    return jDigiDocFacade.addDataFile(is, fileName, mimeType);
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    return jDigiDocFacade.addDataFile(file.getPath(), mimeType);
  }

  @Override
  public void addSignature(Signature signature) {
    logger.info("Ignoring separate add signature call for DDoc containers, because signatures are added to container during signing process");
  }

  @Override
  public List<DataFile> getDataFiles() {
    return jDigiDocFacade.getDataFiles();
  }

  /**
   * Returns container type "BDOC" or "DDOC"
   */
  @Override
  public String getType() {
    return "DDOC";
  }

  @Override
  public List<Signature> getSignatures() {
    return jDigiDocFacade.getSignatures();
  }

  @Override
  public void removeDataFile(DataFile file) {
    jDigiDocFacade.removeDataFile(file.getName());
  }

  @Override
  public void removeSignature(Signature signature) {
    DDocSignature dDocSignature = (DDocSignature) signature;
    jDigiDocFacade.removeSignature(dDocSignature.getIndexInArray());
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    jDigiDocFacade.extendTo(profile);
  }

  @Override
  public File saveAsFile(String fileName) {
    jDigiDocFacade.save(fileName);
    return new File(fileName);
  }

  @Override
  public InputStream saveAsStream() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    jDigiDocFacade.save(outputStream);
    return new ByteArrayInputStream(outputStream.toByteArray());
  }

  @Override
  public ValidationResult validate() {
    return jDigiDocFacade.validate();
  }

  public DDocFacade getJDigiDocFacade() {
    return jDigiDocFacade;
  }
}
