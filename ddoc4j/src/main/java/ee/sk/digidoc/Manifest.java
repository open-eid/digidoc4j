package ee.sk.digidoc;

import ee.sk.utils.ConvertUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;

public class Manifest implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** manifest urn */
    private static final String MANIFEST_URN = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
    public static final String MANIFEST_BDOC_MIME_1_0 = "application/vnd.bdoc-1.0";
    public static final String MANIFEST_BDOC_MIME_1_1 = "application/vnd.bdoc-1.1";
    public static final String MANIFEST_BDOC_MIME_2_0 = "application/vnd.etsi.asic-e+zip";
    /** file entries */
    private ArrayList m_fileEntries;

    /**
     * Default constructor for Manifest
     */
    public Manifest()
    {
        m_fileEntries = null;
    }

    // accessors
    /**
     * Retrieves number of <file-entry> elements
     * @return number of <file-entry> elements
     */
    public int getNumFileEntries() { return ((m_fileEntries != null) ? m_fileEntries.size() : 0); }

    /**
     * Retrieves the desired <file-entry> element
     * @param nIdx index of entry
     * @return desired <file-entry> element or null if not existent
     */
    public ManifestFileEntry getFileEntry(int nIdx) {
        if(nIdx >= 0 && m_fileEntries != null && nIdx < m_fileEntries.size())
            return (ManifestFileEntry)m_fileEntries.get(nIdx);
        else
            return null;
    }

    // mutators

    /**
     * Adds a new <file-entry>
     * @param fe <file-entry> element to add
     */
    public void addFileEntry(ManifestFileEntry fe) {
        if(m_fileEntries == null)
            m_fileEntries = new ArrayList();
        m_fileEntries.add(fe);
    }

    /**
     * Removes a <file-entry>
     * @param nIdx index of entry
     */
    public void removeFileEntry(int nIdx) {
        if(nIdx >= 0 && m_fileEntries != null && nIdx < m_fileEntries.size())
            m_fileEntries.remove(nIdx);
    }

    /**
     * Removes a <file-entry>
     * @param fullPath full-path of entry
     */
    public void removeFileEntryWithPath(String fullPath) {
        for(int i = 0; (m_fileEntries != null) && (i < m_fileEntries.size()); i++) {
            ManifestFileEntry fe = (ManifestFileEntry)m_fileEntries.get(i);
            if(fe.getFullPath().equals(fullPath))
                m_fileEntries.remove(i);
        }
    }

    /**
     * Finds a file-entry by path
     * @param fullPath full-path of entry
     * @return file-entry if found
     */
    public ManifestFileEntry findFileEntryByPath(String fullPath) {
        for(int i = 0; (m_fileEntries != null) && (i < m_fileEntries.size()); i++) {
            ManifestFileEntry fe = (ManifestFileEntry)m_fileEntries.get(i);
            if(fe.getFullPath().equals(fullPath))
                return fe;
        }
        return null;
    }

    /**
     * Converts the Manifest to XML form
     * @return XML representation of Manifest
     */
    public byte[] toXML()
            throws DigiDocException
    {
        ByteArrayOutputStream bos =
                new ByteArrayOutputStream();
        try {
            bos.write(ConvertUtils.str2data("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"));
            //bos.write(ConvertUtils.str2data("<!DOCTYPE manifest:manifest PUBLIC \"-//OpenOffice.org//DTD Manifest 1.0//EN\" \"Manifest.dtd\">\n"));
            bos.write(ConvertUtils.str2data("<manifest:manifest xmlns:manifest=\""));
            bos.write(ConvertUtils.str2data(MANIFEST_URN));
            bos.write(ConvertUtils.str2data("\">\n"));
            for(int i = 0; (m_fileEntries != null) && (i < m_fileEntries.size()); i++) {
                ManifestFileEntry fe = (ManifestFileEntry)m_fileEntries.get(i);
                bos.write(fe.toXML());
            }
            bos.write(ConvertUtils.str2data("</manifest:manifest>\n"));
        } catch(IOException ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * return the stringified form of Manifest
     * @return Manifest string representation
     */
    public String toString() {
        String str = null;
        try {
            str = new String(toXML());
        } catch(Exception ex) {}
        return str;
    }

}
