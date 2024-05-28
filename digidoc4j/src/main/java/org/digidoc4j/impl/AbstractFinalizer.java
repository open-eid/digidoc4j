/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.InvalidDataFileException;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Abstract base class for signature/timestamp finalizers.
 */
public abstract class AbstractFinalizer implements Serializable {

  protected final Configuration configuration;
  protected final List<DataFile> dataFiles;

  /**
   * Creates an instance of the finalizer using the specified configuration and list of datafiles.
   *
   * @param configuration configuration to use
   * @param dataFiles list of datafiles
   *
   * @throws InvalidDataFileException if any of the specified datafiles is empty
   */
  protected AbstractFinalizer(Configuration configuration, List<DataFile> dataFiles) {
    verifyDataFilesNotEmpty(Objects.requireNonNull(dataFiles));
    this.configuration = Objects.requireNonNull(configuration);
    this.dataFiles = dataFiles;
  }

  private static void verifyDataFilesNotEmpty(List<DataFile> dataFiles) {
    dataFiles.stream()
            .filter(DataFile::isFileEmpty)
            .map(dataFile -> "Cannot sign empty datafile: " + dataFile.getName())
            .map(InvalidDataFileException::new)
            .reduce((e1, e2) -> {
                e1.addSuppressed(e2);
                return e1;
            })
            .ifPresent(e -> {
                throw e;
            });
  }

}
