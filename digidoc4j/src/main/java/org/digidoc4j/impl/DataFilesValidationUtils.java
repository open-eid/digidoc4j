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

import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidDataFileException;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility class for validating data files.
 */
public final class DataFilesValidationUtils {

  /**
   * Checks whether the provided list of data files contains empty data files (files with 0-byte size), and returns
   * a list containing an exception for each empty data file.
   * An empty list is returned if no empty data files are encountered.
   *
   * @param dataFiles data files to check
   * @return list of exceptions for empty data files, or an empty list if no empty data files are encountered
   */
  public static List<DigiDoc4JException> getExceptionsForEmptyDataFiles(List<DataFile> dataFiles) {
    return dataFiles.stream()
            .filter(DataFile::isFileEmpty)
            .map(dataFile -> String.format("Data file '%s' is empty", dataFile.getName()))
            .map(InvalidDataFileException::new)
            .collect(Collectors.toList());
  }

  private DataFilesValidationUtils() {
  }

}
