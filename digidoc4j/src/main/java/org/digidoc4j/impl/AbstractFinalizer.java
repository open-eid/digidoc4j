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
import java.util.function.Function;

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
   */
  protected AbstractFinalizer(Configuration configuration, List<DataFile> dataFiles) {
    this.configuration = Objects.requireNonNull(configuration);
    this.dataFiles = Objects.requireNonNull(dataFiles);
  }

  /**
   * Ensures that none of the data files are empty, throwing {@link InvalidDataFileException} in case any empty data
   * files are encountered.
   * On success, returns the initial list of data files unmodified.
   *
   * @param dataFiles list of data files to verify
   * @return initial list of data files
   *
   * @throws InvalidDataFileException if any empty data files are encountered.
   * In case of multiple empty data files, subsequent exceptions are listed as suppressed by the first one.
   */
  protected static List<DataFile> verifyDataFilesNotEmpty(
          List<DataFile> dataFiles,
          Function<DataFile, String> exceptionMessageResolver
  ) throws InvalidDataFileException {
    dataFiles.stream()
            .filter(DataFile::isFileEmpty)
            .map(exceptionMessageResolver)
            .map(InvalidDataFileException::new)
            .reduce((e1, e2) -> {
                e1.addSuppressed(e2);
                return e1;
            })
            .ifPresent(e -> {
                throw e;
            });

    return dataFiles;
  }

}
