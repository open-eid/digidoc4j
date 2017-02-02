package org.digidoc4j.test.filename;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.main.DigiDoc4J;
import org.junit.Test;

public class FileNameTest extends DigiDoc4JTestHelper {

  private Pattern special = Pattern.compile(DigiDoc4J.SPECIAL_CHARACTERS);

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
