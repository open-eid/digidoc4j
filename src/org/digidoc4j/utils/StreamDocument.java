package org.digidoc4j.utils;


import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.api.exceptions.DigiDoc4JException;

import java.io.*;

public class StreamDocument implements DSSDocument {
  private static final int MAX_SIZE_IN_MEMORY = 1024 * 5;
  String documentName;
  MimeType mimeType;
  File temporaryFile;

  //TODO if file is small enough you can read it into byte[] and cache it
  public StreamDocument(InputStream stream, String documentName, MimeType mimeType) {
    fillByteArray(stream);

    this.documentName = documentName;
    this.mimeType = mimeType;
  }

  private void fillByteArray(InputStream stream) {
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
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(out);
    }
  }


  @Override
  public InputStream openStream() throws DSSException {
    try {
      return new FileInputStream(temporaryFile);
    } catch (FileNotFoundException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public byte[] getBytes() throws DSSException {
    try {
      return IOUtils.toByteArray(new FileInputStream(temporaryFile));
    } catch (IOException e) {
      throw new DSSException(e.getCause());
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
        IOUtils.copy(new FileInputStream(temporaryFile), fileOutputStream);
      } finally {
        fileOutputStream.close();
      }
    } catch (IOException e) {
      throw new DigiDoc4JException(e);
    }
  }

  @Override
  public String getDigest(DigestAlgorithm digestAlgorithm) {
    byte[] digestBytes;
    try {
      digestBytes = DSSUtils.digest(digestAlgorithm, new FileInputStream(temporaryFile));
    } catch (FileNotFoundException e) {
      throw new DigiDoc4JException(e);
    }
    return DSSUtils.base64Encode(digestBytes);
  }
}
