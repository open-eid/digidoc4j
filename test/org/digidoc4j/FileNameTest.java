package org.digidoc4j;

import static org.digidoc4j.utils.Helper.deleteFile;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.utils.Helper;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class FileNameTest extends DigiDoc4JTestHelper {

  private Pattern special = Pattern.compile(Helper.SPECIAL_CHARACTERS);

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

    deleteFile(tempFolder.getPath());

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

    deleteFile(tempFolder.getPath());

    assertTrue(new File("testFiles/cgi-test-container.bdoc").exists());
  }

  @Test
  public void validateSpacialCharactersInPath() throws Exception {
    String fileName = "testFiles/test.txt";

    File file = new File(fileName);
    if (file.exists() && !file.isDirectory()) {
      Matcher hasSpecial = special.matcher(file.getName());
      assertFalse(hasSpecial.find());
    }
  }

  @Test
  public void validateSpacialCharacters() throws Exception {
    String fileName = "test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertFalse(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersLessThanEnd() throws Exception {
    String fileName = "test<.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersLessThanStart() throws Exception {
    String fileName = "<test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersLessThanMidle() throws Exception {
    String fileName = "te<st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersGreaterThanEnd() throws Exception {
    String fileName = "test>.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersGreaterThanStart() throws Exception {
    String fileName = ">test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersGreaterThanMidle() throws Exception {
    String fileName = "te>st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharacterColonEnd() throws Exception {
    String fileName = "test:.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersColonStart() throws Exception {
    String fileName = ":test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersColonMidle() throws Exception {
    String fileName = "te:st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersDoubleQuoteEnd() throws Exception {
    String fileName = "test\".txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersDoubleQuoteStart() throws Exception {
    String fileName = "\"test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersDoubleQuoteMidle() throws Exception {
    String fileName = "te\"st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersfForwardSlashEnd() throws Exception {
    String fileName = "test/.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersForwardSlashStart() throws Exception {
    String fileName = "/test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersForwardSlashMidle() throws Exception {
    String fileName = "te/st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersBackslashEnd() throws Exception {
    String fileName = "test\\.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersBackslashStart() throws Exception {
    String fileName = "\\test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersBackslashMidle() throws Exception {
    String fileName = "te\\st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersPipeEnd() throws Exception {
    String fileName = "test|.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersPipeStart() throws Exception {
    String fileName = "|test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersPipeMidle() throws Exception {
    String fileName = "te|st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersQuestionMarkEnd() throws Exception {
    String fileName = "test?.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersQuestionMarkStart() throws Exception {
    String fileName = "?test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersQuestionMarkMidle() throws Exception {
    String fileName = "te?st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersAsteriskEnd() throws Exception {
    String fileName = "test*.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersAsteriskStart() throws Exception {
    String fileName = "*test.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }

  @Test
  public void validateSpacialCharactersAsteriskMidle() throws Exception {
    String fileName = "te*st.txt";
    Matcher hasSpecial = special.matcher(fileName);
    assertTrue(hasSpecial.find());
  }
}
