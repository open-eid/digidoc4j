package org.digidoc4j.impl.bdoc;

import java.io.File;
import java.io.InputStream;
import java.util.List;

import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.AsicFacade;

public class BDocContainer implements Container {

  private AsicFacade asicFacade;

  public BDocContainer(AsicFacade asicFacade) {
    this.asicFacade = asicFacade;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    return asicFacade.addDataFile(path, mimeType);
  }

  @Override
  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    return asicFacade.addDataFile(is, fileName, mimeType);
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    return asicFacade.addDataFile(file.getPath(), mimeType);
  }

  @Override
  public void addSignature(Signature signature) {
    asicFacade.addSignature(signature);
  }

  @Override
  public List<DataFile> getDataFiles() {
    return asicFacade.getDataFiles();
  }

  @Override
  public String getType() {
    return "BDOC";
  }

  @Override
  public List<Signature> getSignatures() {
    return asicFacade.getSignatures();
  }

  @Override
  public void removeDataFile(DataFile file) {
    asicFacade.removeDataFile(file.getName());
  }

  @Override
  public void removeSignature(Signature signature) {
    asicFacade.removeSignature(signature);
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    asicFacade.extendTo(profile);
  }

  @Override
  public File saveAsFile(String filePath) {
    asicFacade.save(filePath);
    return new File(filePath);
  }

  @Override
  public InputStream saveAsStream() {
    return asicFacade.saveAsStream();
  }

  @Override
  public ValidationResult validate() {
    return asicFacade.validate();
  }

  public AsicFacade getAsicFacade() {
    return asicFacade;
  }
}
