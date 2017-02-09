package org.digidoc4j;

import static org.digidoc4j.utils.Helper.deleteFile;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;

import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.utils.Helper;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class FileNameTest extends DigiDoc4JTestHelper {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @After
  public void cleanUp() throws Exception {
    deleteFile("testFiles/cgi-test-container.bdoc");
  }

  @Test(expected = InvalidDataFileException.class)
  public void createContainerWithSpecialCharactersInFileName()
      throws Exception {

    File tempFolder = testFolder.newFolder();
    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    FileInputStream fis = new FileInputStream(
        "testFiles/special-char-files/dds_acrobat.pdf");

    Container container = ContainerBuilder.aContainer("BDOC")
        .withConfiguration(configuration).withDataFile(fis,
            "xxx,%2003:1737,%2031.08.2015.a.pdf", "application/pdf")
        .usingTempDirectory(tempFolder.getPath()).build();

    container.saveAsFile("testFiles/cgi-test-container.bdoc");

    fis.close();

    assertFalse(new File("testFiles/cgi-test-container.bdoc").exists());
  }

  @Test
  public void createContainer() throws Exception {

    File tempFolder = testFolder.newFolder();

    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    FileInputStream fis = new FileInputStream(
        "testFiles/special-char-files/dds_acrobat.pdf");

    Container container = ContainerBuilder.aContainer("BDOC")
        .withConfiguration(configuration)
        .withDataFile(fis, "cgi.pdf", "application/pdf")
        .usingTempDirectory(tempFolder.getPath()).build();

    container.saveAsFile("testFiles/cgi-test-container.bdoc");

    fis.close();

    assertTrue(new File("testFiles/cgi-test-container.bdoc").exists());
  }

  @Test
  public void validateSpecialialCharacters() throws Exception {
    String fileName = "test.txt";
    assertFalse(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersLessThanEnd() throws Exception {
    String fileName = "test<.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersLessThanStart() throws Exception {
    String fileName = "<test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersLessThanMidle() throws Exception {
    String fileName = "te<st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersGreaterThanEnd() throws Exception {
    String fileName = "test>.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersGreaterThanStart() throws Exception {
    String fileName = ">test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersGreaterThanMidle() throws Exception {
    String fileName = "te>st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharacterColonEnd() throws Exception {
    String fileName = "test:.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersColonStart() throws Exception {
    String fileName = ":test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersColonMidle() throws Exception {
    String fileName = "te:st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersDoubleQuoteEnd() throws Exception {
    String fileName = "test\".txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersDoubleQuoteStart() throws Exception {
    String fileName = "\"test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersDoubleQuoteMidle() throws Exception {
    String fileName = "te\"st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersfForwardSlashEnd() throws Exception {
    String fileName = "test/.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersForwardSlashStart() throws Exception {
    String fileName = "/test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersForwardSlashMidle() throws Exception {
    String fileName = "te/st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersBackslashEnd() throws Exception {
    String fileName = "test\\.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersBackslashStart() throws Exception {
    String fileName = "\\test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersBackslashMidle() throws Exception {
    String fileName = "te\\st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersPipeEnd() throws Exception {
    String fileName = "test|.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersPipeStart() throws Exception {
    String fileName = "|test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersPipeMidle() throws Exception {
    String fileName = "te|st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersQuestionMarkEnd() throws Exception {
    String fileName = "test?.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersQuestionMarkStart() throws Exception {
    String fileName = "?test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersQuestionMarkMidle() throws Exception {
    String fileName = "te?st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersAsteriskEnd() throws Exception {
    String fileName = "test*.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersAsteriskStart() throws Exception {
    String fileName = "*test.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }

  @Test
  public void validateSpecialCharactersAsteriskMidle() throws Exception {
    String fileName = "te*st.txt";
    assertTrue(Helper.hasSpecialCharacters(fileName));
  }
}
