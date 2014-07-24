package eu.europa.ec.markt.dss.signature;


import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import org.apache.commons.io.IOUtils;

import java.io.*;

public class StreamDocument implements DSSDocument {
  private static final int MAX_SIZE_IN_MEMORY = 1024 * 5;
  String documentName;
  MimeType mimeType;
  File temporaryFile;

  //TODO if file is small enough you can read it into byte[] and cache it
  public StreamDocument(InputStream stream, String documentName, MimeType mimeType) {
    createTemporaryFileOfStream(stream);
    this.documentName = documentName;
    this.mimeType = mimeType;
  }

  private void createTemporaryFileOfStream(InputStream stream) {
    byte[] bytes = new byte[MAX_SIZE_IN_MEMORY];

    FileOutputStream out = null;

    try {
      temporaryFile = File.createTempFile("digidoc4j", ".tmp");
      out = new FileOutputStream(temporaryFile);
      int result;
      while ((result = stream.read(bytes)) > 0) {
        out.write(bytes, 0, result);
      }
      out.flush();
    } catch (IOException e) {
      throw new DSSException(e);
    } finally {
      IOUtils.closeQuietly(out);
    }
  }


  @Override
  public InputStream openStream() throws DSSException {
    try {
      return getTemporaryFileAsStream();
    } catch (FileNotFoundException e) {
      throw new DSSException(e);
    }
  }

  FileInputStream getTemporaryFileAsStream() throws FileNotFoundException {
    return new FileInputStream(temporaryFile);
  }

  @Override
  public byte[] getBytes() throws DSSException {
    try {
      return IOUtils.toByteArray(getTemporaryFileAsStream());
    } catch (IOException e) {
      throw new DSSException(e);
    }
  }

  @Override
  public String getName() {
    return documentName;
  }

  @Override
  public String getAbsolutePath() {
    return temporaryFile.getAbsolutePath();
  }

  @Override
  public MimeType getMimeType() {
    return mimeType;
  }

  @Override
  public void setMimeType(MimeType mimeType) {
    this.mimeType = mimeType;
  }

  @Override
  public void save(String filePath) {
    try {
      FileOutputStream fileOutputStream = new FileOutputStream(filePath);
      try {
        IOUtils.copy(getTemporaryFileAsStream(), fileOutputStream);
      } finally {
        fileOutputStream.close();
      }
    } catch (IOException e) {
      throw new DSSException(e);
    }
  }

  @Override
  public String getDigest(DigestAlgorithm digestAlgorithm) {
    byte[] digestBytes;
    try {
      digestBytes = DSSUtils.digest(digestAlgorithm, getTemporaryFileAsStream());
    } catch (FileNotFoundException e) {
      throw new DSSException(e);
    }
    return DSSUtils.base64Encode(digestBytes);
  }
}
