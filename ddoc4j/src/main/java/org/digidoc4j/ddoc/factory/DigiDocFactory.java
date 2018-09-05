package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.Signature;
import org.digidoc4j.ddoc.SignedDoc;

import java.io.InputStream;
import java.util.List;

public interface DigiDocFactory {

    /**
     * initializes the implementation class
     */
    public void init()
            throws DigiDocException;

    /**
     * Checks filename extension if this is bdoc / asic-e
     * @param fname filename
     * @return true if this is bdoc / asic-e
     */
    public boolean isBdocExtension(String fname);

    /**
     * Reads in a DigiDoc file
     * @param fileName file name
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDoc(String fileName)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc file.This method reads only data in digidoc format. Not BDOC!
     * @param digiDocStream opened stream with DigiDoc data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public SignedDoc readDigiDocFromStream(InputStream digiDocStream)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * @param is opened stream with DigiDoc/BDOC data
     * The user must open and close it.
     * @param isBdoc true if bdoc is read
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocFromStreamOfType(InputStream is, boolean isBdoc)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc or BDOC file
     * @param fname filename
     * @param isBdoc true if bdoc is read
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocOfType(String fname, boolean isBdoc)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc or BDOC file
     * @param fname filename
     * @param isBdoc true if bdoc is read
     * @param lerr list of errors to be filled. If not null then no exceptions are thrown
     * but returned in this array
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocOfType(String fname, boolean isBdoc, List lerr)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * @param is opened stream with DigiDoc/BDOC data
     * The user must open and close it.
     * @param isBdoc true if bdoc is read
     * @param lerr list of errors to be filled. If not null then no exceptions are thrown
     * but returned in this array
     * @return signed document object if successfully parsed
     */
    public SignedDoc readSignedDocFromStreamOfType(InputStream is, boolean isBdoc, List lerr)
            throws DigiDocException;

    /**
     * Reads in only one <Signature>
     * @param sdoc SignedDoc to add this signature to
     * @param sigStream opened stream with Signature data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public Signature readSignature(SignedDoc sdoc, InputStream sigStream)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc file
     * @param digiSigStream opened stream with Signature data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     */
    public Signature readSignature(InputStream digiSigStream)
            throws DigiDocException;

    /**
     * Set temp dir used to cache data files.
     * @param s directory name
     */
    public void setTempDir(String s);

}
