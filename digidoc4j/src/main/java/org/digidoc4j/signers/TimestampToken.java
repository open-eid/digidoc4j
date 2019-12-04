/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.signers;

import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.tsp.TimeStampToken;
import org.digidoc4j.Configuration;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.SkDataLoader;
import org.digidoc4j.impl.SkTimestampDataLoader;
import org.digidoc4j.utils.Helper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Timestamp token for AsicS container
 * <p>
 * Created by Andrei on 7.12.2017.
 */
public final class TimestampToken {

  private TimestampToken() {
  }

  /**
   * generates timesstamp token for AsicS container
   *
   * @param digestAlgorithm
   * @param dataFiles
   * @return DataFile timestamp token
   */
  public static DataFile generateTimestampToken(DigestAlgorithm digestAlgorithm,
                                                List<ContainerBuilder.ContainerDataFile> dataFiles,
                                                Configuration configuration) {
    if (dataFiles.isEmpty()) {
      throw new DigiDoc4JException("Add data file first");
    }
    if (dataFiles.size() > 1) {
      throw new DigiDoc4JException("Supports only asics with only one datafile");
    }
    ContainerBuilder.ContainerDataFile containerDataFile = dataFiles.get(0);
    OnlineTSPSource onlineTSPSource = defineOnlineTSPSource(configuration);
    byte[] dataFileDigest = getDigest(containerDataFile);
    byte[] digest = DSSUtils.digest(digestAlgorithm, dataFileDigest);
    DataFile timeStampToken = getTimestampToken(onlineTSPSource, digestAlgorithm, digest);
    return timeStampToken;
  }

  /**
   * generates timesstamp token for AsicS container
   *
   * @param digestAlgorithm
   * @param containerDataFile
   * @return DataFile timestamp token
   */
  public static DataFile generateTimestampToken(DigestAlgorithm digestAlgorithm, DataFile containerDataFile) {
    OnlineTSPSource onlineTSPSource = defineOnlineTSPSource(null);
    byte[] dataFileDigest;
    dataFileDigest = containerDataFile.getBytes();
    byte[] digest = DSSUtils.digest(digestAlgorithm, dataFileDigest);
    DataFile timeStampToken = getTimestampToken(onlineTSPSource, digestAlgorithm, digest);
    return timeStampToken;
  }

  private static OnlineTSPSource defineOnlineTSPSource(Configuration configuration) {
    OnlineTSPSource source = new OnlineTSPSource();
    if (configuration == null) {
      configuration = Configuration.getInstance();
    }
    source.setTspServer(configuration.getTspSource());
    SkDataLoader loader = new SkTimestampDataLoader(configuration);
    loader.setUserAgent(Helper.createBDocAsicSUserAgent());
    source.setDataLoader(loader);
    return source;
  }

  private static DataFile getTimestampToken(OnlineTSPSource onlineTSPSource, DigestAlgorithm digestAlgorithm,
                                            byte[] digest) {
    DataFile timeStampToken = new DataFile();
    TimeStampToken timeStampResponse = onlineTSPSource.getTimeStampResponse(digestAlgorithm, digest);
    String timestampFilename = "timestamp";
    timeStampToken.setDocument(
        new InMemoryDocument(DSSASN1Utils.getEncoded(timeStampResponse), timestampFilename, MimeType.TST));
    timeStampToken.setMediaType(MimeType.TST.getMimeTypeString());
    return timeStampToken;
  }

  private static byte[] getDigest(ContainerBuilder.ContainerDataFile dataFile) {
    try {
      byte[] dataFileDigest;
      if (!dataFile.isStream) {
        Path path = Paths.get(dataFile.filePath);
        dataFileDigest = Files.readAllBytes(path);
      } else {
        dataFileDigest = IOUtils.toByteArray(dataFile.inputStream);
      }
      return dataFileDigest;
    } catch (IOException e) {
      e.printStackTrace();
    }
    throw new DigiDoc4JException("Cannot get file digest");
  }

}
