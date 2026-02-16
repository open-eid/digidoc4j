/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import java.io.File;
import java.io.FileInputStream;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.utils.Helper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class FileNameTest extends AbstractTest {

  @Test
  public void createContainerWithSpecialCharactersInFileName() throws Exception {
    try (FileInputStream stream = new FileInputStream("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf")) {
      ContainerBuilder containerBuilder = ContainerBuilder.aContainer();

      assertThrows(
              InvalidDataFileException.class,
              () -> containerBuilder.withDataFile(stream, "xxx,%2003:1737,%2031.08.2015.a.pdf", MimeTypeEnum.PDF.getMimeTypeString())
      );
    }
  }

  @Test
  public void createContainer() throws Exception {
    File folder = createTempDirectoryInTestFolderAndReturnFile();
    try (FileInputStream stream = new FileInputStream("src/test/resources/testFiles/special-char-files/dds_acrobat.pdf")) {
      Container container = ContainerBuilder.aContainer().withDataFile(stream, "cgi.pdf", MimeTypeEnum.PDF.getMimeTypeString())
          .usingTempDirectory(folder.getPath()).build();
      String file = getFileBy("bdoc");
      container.saveAsFile(file);
      assertTrue(new File(file).exists());
    }
  }

  @Test
  public void validateSpecialialCharacters() {
    String fileName = "test.txt";
    assertFalse(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersLessThanEnd() {
    String fileName = "test<.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersLessThanStart() {
    String fileName = "<test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersLessThanMidle() {
    String fileName = "te<st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersGreaterThanEnd() {
    String fileName = "test>.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersGreaterThanStart() {
    String fileName = ">test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersGreaterThanMidle() {
    String fileName = "te>st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharacterColonEnd() {
    String fileName = "test:.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersColonStart() {
    String fileName = ":test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersColonMidle() {
    String fileName = "te:st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersDoubleQuoteEnd() {
    String fileName = "test\".txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersDoubleQuoteStart() {
    String fileName = "\"test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersDoubleQuoteMidle() {
    String fileName = "te\"st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersfForwardSlashEnd() {
    String fileName = "test/.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersForwardSlashStart() {
    String fileName = "/test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersForwardSlashMidle() {
    String fileName = "te/st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersBackslashEnd() {
    String fileName = "test\\.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersBackslashStart() {
    String fileName = "\\test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersBackslashMidle() {
    String fileName = "te\\st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersPipeEnd() {
    String fileName = "test|.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersPipeStart() {
    String fileName = "|test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersPipeMidle() {
    String fileName = "te|st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersQuestionMarkEnd() {
    String fileName = "test?.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersQuestionMarkStart() {
    String fileName = "?test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersQuestionMarkMidle() {
    String fileName = "te?st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersAsteriskEnd() {
    String fileName = "test*.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersAsteriskStart() {
    String fileName = "*test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersAsteriskMidle() {
    String fileName = "te*st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

}
