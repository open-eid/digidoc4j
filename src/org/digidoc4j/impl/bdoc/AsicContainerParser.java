package org.digidoc4j.impl.bdoc;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.signature.DSSDocument;

public class AsicContainerParser {

  private final static Logger logger = LoggerFactory.getLogger(AsicContainerParser.class);
  //Matches META-INF/*signatures*.xml where the last * is a number
  private static final String SIGNATURES_FILE_REGEX = "META-INF/(.*)signatures(\\d+).xml";
  private static final Pattern SIGNATURE_FILE_ENDING_PATTERN = Pattern.compile("(\\d+).xml");
  private DSSDocument asicContainer;

  public AsicContainerParser(DSSDocument asicContainer) {
    this.asicContainer = asicContainer;
  }

  public Integer findCurrentSignatureFileIndex() throws InvalidAsicContainerException {
    logger.debug("Finding the current signature file index of the container");
    try {
      Integer currentSignatureFileIndex = null;
      ZipInputStream docStream = new ZipInputStream(asicContainer.openStream());
      ZipEntry entry = docStream.getNextEntry();
      while (entry != null) {
        String entryName = entry.getName();
        if(isSignaturesFile(entryName)) {
          logger.debug("Signatures file name: " + entryName);
          int fileIndex = extractSignaturesFileIndex(entryName);
          if(currentSignatureFileIndex == null || currentSignatureFileIndex <= fileIndex) {
            currentSignatureFileIndex = fileIndex;
          }
        }
        entry = docStream.getNextEntry();
      }
      logger.debug("The current signature file index is " + currentSignatureFileIndex);
      return currentSignatureFileIndex;
    } catch (IOException e) {
      logger.error("Invalid asic container: " + e.getMessage());
      throw new InvalidAsicContainerException(e);
    }
  }

  private boolean isSignaturesFile(String entryName) {
    return entryName.matches(SIGNATURES_FILE_REGEX);
  }

  private int extractSignaturesFileIndex(String entryName) {
    Matcher fileEndingMatcher = SIGNATURE_FILE_ENDING_PATTERN.matcher(entryName);
    fileEndingMatcher.find();
    String fileEnding = fileEndingMatcher.group();
    String indexNumber = fileEnding.replace(".xml", "");
    return Integer.parseInt(indexNumber);
  }

  public static class InvalidAsicContainerException extends RuntimeException {
    public InvalidAsicContainerException(Exception e) {
      super(e);
    }
  }
}
