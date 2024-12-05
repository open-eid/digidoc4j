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
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class DataFilesValidationUtilsTest {

  @Test
  public void getExceptionsForEmptyDataFiles_WhenDataFilesListIsEmpty_ReturnsEmptyExceptionList() {
    List<DigiDoc4JException> result = DataFilesValidationUtils.getExceptionsForEmptyDataFiles(Collections.emptyList());

    assertThat(result, empty());
  }

  @Test
  public void getExceptionsForEmptyDataFiles_WhenDataFilesListContainsNonEmptyDataFile_ReturnsEmptyExceptionList() {
    DataFile nonEmptyDataFile = mockNonEmptyDataFile();
    List<DataFile> dataFiles = Collections.singletonList(nonEmptyDataFile);

    List<DigiDoc4JException> result = DataFilesValidationUtils.getExceptionsForEmptyDataFiles(dataFiles);

    assertThat(result, empty());
    verify(nonEmptyDataFile).isFileEmpty();
    verifyNoMoreInteractions(nonEmptyDataFile);
  }

  @Test
  public void getExceptionsForEmptyDataFiles_WhenDataFilesListContainsEmptyDataFile_ReturnsExceptionForEmptyDataFile() {
    DataFile emptyDataFile = mockEmptyDataFile("data-file-name.ext");
    List<DataFile> dataFiles = Collections.singletonList(emptyDataFile);

    List<DigiDoc4JException> result = DataFilesValidationUtils.getExceptionsForEmptyDataFiles(dataFiles);

    assertThat(result, hasSize(1));
    assertThat(result.get(0), instanceOf(InvalidDataFileException.class));
    assertThat(result.get(0).getMessage(), equalTo("Data file 'data-file-name.ext' is empty"));
    verify(emptyDataFile).isFileEmpty();
    verify(emptyDataFile).getName();
    verifyNoMoreInteractions(emptyDataFile);
  }

  @Test
  public void getExceptionsForEmptyDataFiles_WhenDataFilesListContainsEmptyDataFileAmongNonEmpty_ReturnsExceptionForEmptyDataFile() {
    DataFile nonEmptyDataFile1 = mockNonEmptyDataFile();
    DataFile emptyDataFile2 = mockEmptyDataFile("data-file-2-name.ext");
    DataFile nonEmptyDataFile3 = mockNonEmptyDataFile();
    List<DataFile> dataFiles = Arrays.asList(nonEmptyDataFile1, emptyDataFile2, nonEmptyDataFile3);

    List<DigiDoc4JException> result = DataFilesValidationUtils.getExceptionsForEmptyDataFiles(dataFiles);

    assertThat(result, hasSize(1));
    assertThat(result.get(0), instanceOf(InvalidDataFileException.class));
    assertThat(result.get(0).getMessage(), equalTo("Data file 'data-file-2-name.ext' is empty"));
    verify(nonEmptyDataFile1).isFileEmpty();
    verify(emptyDataFile2).isFileEmpty();
    verify(emptyDataFile2).getName();
    verify(nonEmptyDataFile3).isFileEmpty();
    verifyNoMoreInteractions(nonEmptyDataFile1, emptyDataFile2, nonEmptyDataFile3);
  }

  @Test
  public void getExceptionsForEmptyDataFiles_WhenDataFilesListContainsMultipleEmptyDataFiles_ReturnsExceptionsForAllEmptyDataFiles() {
    DataFile emptyDataFile1 = mockEmptyDataFile("data-file-1-name.ext");
    DataFile nonEmptyDataFile2 = mockNonEmptyDataFile();
    DataFile emptyDataFile3 = mockEmptyDataFile("data-file-3-name.ext");
    List<DataFile> dataFiles = Arrays.asList(emptyDataFile1, nonEmptyDataFile2, emptyDataFile3);

    List<DigiDoc4JException> result = DataFilesValidationUtils.getExceptionsForEmptyDataFiles(dataFiles);

    assertThat(result, hasSize(2));
    assertThat(result.get(0), instanceOf(InvalidDataFileException.class));
    assertThat(result.get(0).getMessage(), equalTo("Data file 'data-file-1-name.ext' is empty"));
    assertThat(result.get(1), instanceOf(InvalidDataFileException.class));
    assertThat(result.get(1).getMessage(), equalTo("Data file 'data-file-3-name.ext' is empty"));
    verify(emptyDataFile1).isFileEmpty();
    verify(emptyDataFile1).getName();
    verify(nonEmptyDataFile2).isFileEmpty();
    verify(emptyDataFile3).isFileEmpty();
    verify(emptyDataFile3).getName();
    verifyNoMoreInteractions(emptyDataFile1, nonEmptyDataFile2, emptyDataFile3);
  }

  private static DataFile mockEmptyDataFile(String name) {
    DataFile dataFile = mock(DataFile.class);
    doReturn(true).when(dataFile).isFileEmpty();
    doReturn(name).when(dataFile).getName();
    return dataFile;
  }

  private static DataFile mockNonEmptyDataFile() {
    DataFile dataFile = mock(DataFile.class);
    doReturn(false).when(dataFile).isFileEmpty();
    return dataFile;
  }

}
