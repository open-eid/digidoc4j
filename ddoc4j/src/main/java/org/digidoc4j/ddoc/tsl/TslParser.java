/*
 * TslParser.java
 * ETSI TS 102 231 V3.1.1. TSL xml format parser
 * AUTHOR:  Veiko Sinivee, Sunset Software OÜ
 *==================================================
 * Copyright (C) AS Sertifitseerimiskeskus
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */
package org.digidoc4j.ddoc.tsl;

import org.digidoc4j.ddoc.Base64Util;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.factory.SAXDigiDocException;
import org.digidoc4j.ddoc.utils.ConvertUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Stack;


/**
 * ETSI TS 102 231 V3.1.1. TSL xml format parser
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class TslParser extends DefaultHandler
{
	/** log4j logger */
    private static Logger m_logger = LoggerFactory.getLogger(TslParser.class);
    private Stack m_tags;
    private TrustServiceStatusList m_tsl;
    private StringBuffer m_sbCollectItem;
    private SchemeInformation m_si;
    private TrustServiceProvider m_tsp;
    private MultiLangString m_mls;
    private PostalAddress m_adr;
    private TSPService m_tsps;
    private Quality m_qual;
    
	/**
	 * Reads in a TSL file
	 * @param is opened stream with TSL data
	 * The user must open and close it.
	 * @return TSL
	 */
	public TrustServiceStatusList readTSL(InputStream is)
		throws DigiDocException
	{
		// Use an instance of ourselves as the SAX event handler
		TslParser handler = this;
		// Use the default (non-validating) parser
		SAXParserFactory factory = SAXParserFactory.newInstance();
		try {
			factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
			factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			SAXParser saxParser = factory.newSAXParser();
			saxParser.parse(is, handler);
		} catch (SAXDigiDocException ex) {
			throw ex.getDigiDocException();
		} catch (Exception ex) {
			DigiDocException.handleException(ex, DigiDocException.ERR_PARSE_XML);
		}
		if (m_tsl == null)
			throw new DigiDocException(DigiDocException.ERR_DIGIDOC_FORMAT,
				"This document is not in TSL format", null);
		return m_tsl;
	}
    
	/**
	 * Start Document handler
	 */
	public void startDocument() throws SAXException {
		m_tags = new Stack();
		m_tsl = null;
		m_sbCollectItem = null;
		m_si = null;
		m_tsp = null;
		m_mls = null;
		m_adr = null;
		m_tsps = null;
		m_qual = null;
	}
	
	/**
	 * End Document handler
	 */
	public void endDocument() throws SAXException {
		
	}
	
	private String getAttrValue(Attributes attrs, String key)
	{
		for(int i = 0; i < attrs.getLength(); i++) {
			String key2 = attrs.getQName(i);
			if(m_logger.isDebugEnabled())
				m_logger.debug("Attr: " + key2 + " value: " + attrs.getValue(i));
			//System.out.println("Attr: " + key2 + " value: " + attrs.getValue(i));
			if(key2.indexOf(key) != -1) 
				return attrs.getValue(i);
		}
		return null;
	}
	
	private boolean findTagOnStack(String tag)
	{
		java.util.Enumeration eTags = m_tags.elements();
		while(eTags.hasMoreElements()) {
			String t2 = (String)eTags.nextElement();
			if(t2.equals(tag))
				return true;
		}
		return false;
	}
	
	/**
	 * Start Element handler
	 * @param namespaceURI namespace URI
	 * @param lName local name
	 * @param qName qualified name
	 * @param attrs attributes
	 */
	public void startElement(String namespaceURI, String lName, String qName, Attributes attrs)
		throws SAXDigiDocException
	{
		//if(m_logger.isDebugEnabled())
		//	m_logger.debug("Start Element: "	+ qName + " lname: "  + lName + " uri: " + namespaceURI);
		String tag = qName;
		if(tag.indexOf(':') != -1) {
			tag = qName.substring(qName.indexOf(':') + 1);
		}
		m_tags.push(tag);
		m_sbCollectItem = new StringBuffer();
		
		// <TrustServiceStatusList>
		if(tag.equals("TrustServiceStatusList"))
			m_tsl = new TrustServiceStatusList();
		// <SchemeInformation>
		if(tag.equals("SchemeInformation")) {
			m_si = new SchemeInformation();
			if(m_tsl != null)
				m_tsl.setSchemeInformation(m_si);
		}
		// <PostalAddress>
		if(tag.equals("PostalAddress")) {
			m_adr = new PostalAddress();
			if(m_si != null && findTagOnStack("SchemeOperatorAddress")) 
				m_si.addPostalAddress(m_adr);
			if(m_tsp != null && m_tsp.getTSPInformation() != null && findTagOnStack("TSPAddress"))
				m_tsp.getTSPInformation().addPostalAddress(m_adr);
			
		}
		// <URI>
		if(tag.equals("URI")) {
			m_mls = new MultiLangString();
			m_mls.setLang(getAttrValue(attrs, "lang"));
			if(m_si != null && findTagOnStack("SchemeOperatorAddress"))
				m_si.addElectronicAddress(m_mls);
			if(m_si != null && findTagOnStack("SchemeTypeCommunityRules"))
				m_si.addSchemeTypeCommunityRule(m_mls);
			if(m_si != null && findTagOnStack("DistributionPoints"))
				m_si.addDistributionPoint(m_mls);
			if(m_si != null && findTagOnStack("SchemeInformationURI"))
				m_si.addSchemeInformationURI(m_mls);
			if(m_tsp != null && m_tsp.getTSPInformation() != null && findTagOnStack("TSPAddress"))
				m_tsp.getTSPInformation().addElectronicAddress(m_mls);
			if(m_tsp != null && m_tsp.getTSPInformation() != null && findTagOnStack("TSPInformationURI"))
				m_tsp.getTSPInformation().addInformationURI(m_mls);
			if(m_tsps != null && findTagOnStack("TSPServiceDefinitionURI"))
				m_tsps.addServiceDefinitionURI(m_mls);
			
		}
		// <TSLLegalNotice>
		if(tag.equals("TSLLegalNotice")) {
			m_mls = new MultiLangString();
			m_mls.setLang(getAttrValue(attrs, "lang"));
			if(m_si != null)
				m_si.addPolicyOrLegalNotice(m_mls);
		}
		
		// <Name>
		if(tag.equals("Name")) {
			m_mls = new MultiLangString();
			m_mls.setLang(getAttrValue(attrs, "lang"));
			if(m_si != null && findTagOnStack("SchemeOperatorName"))
				m_si.addOperatorName(m_mls);
			if(m_si != null && findTagOnStack("SchemeName"))
				m_si.addSchemeName(m_mls);
			if(m_tsp != null && m_tsp.getTSPInformation() != null && findTagOnStack("TSPName"))
				m_tsp.getTSPInformation().addName(m_mls);
			if(m_tsp != null && m_tsp.getTSPInformation() != null && findTagOnStack("TSPTradeName"))
				m_tsp.getTSPInformation().addTradeName(m_mls);
			if(m_tsps != null)
				m_tsps.addName(m_mls);
			
		}
		// <TrustServiceProvider>
		if(tag.equals("TrustServiceProvider")) {
			m_tsp = new TrustServiceProvider();
			if(m_tsl != null)
				m_tsl.addTrustServiceProvider(m_tsp);
		}
		// <TSPInformation>
		if(tag.equals("TSPInformation")) {
			if(m_tsp != null)
				m_tsp.setTSPInformation(new TSPInformation());
		}
		// <TSPService>
		if(tag.equals("TSPService")) {
			m_tsps = new TSPService();
			if(m_tsp != null)
				m_tsp.addTSPService(m_tsps);
		}
		// <QualityElement>
		if(tag.equals("QualityElement")) {
			m_qual = new Quality();
			if(m_tsps != null)
				m_tsps.addQuality(m_qual);
		}
		
	}
	
	/**
	 * End Element handler
	 * @param namespaceURI namespace URI
	 * @param lName local name
	 * @param qName qualified name
	 */
	public void endElement(String namespaceURI, String sName, String qName)
		throws SAXException 
	{
		//if(m_logger.isDebugEnabled())
		//	m_logger.debug("End Element: " + qName);
		// remove last tag from stack
		String tag = qName;
		String nsPref = null;
		if(tag.indexOf(':') != -1) {
			tag = qName.substring(qName.indexOf(':') + 1);
			nsPref = qName.substring(0, qName.indexOf(':'));
		}
		String currTag = (String) m_tags.pop();
	
		
		// </SchemeInformation>
		if(tag.equals("SchemeInformation"))
			m_si = null;
		// </TSLVersionIdentifier>
		if(tag.equals("TSLVersionIdentifier")) {
			if(m_si != null)
				m_si.setVersionIdentifier(Integer.parseInt(m_sbCollectItem.toString()));
		}
		// </TSLSequenceNumber>
		if(tag.equals("TSLSequenceNumber")) {
			if(m_si != null)
				m_si.setSequenceNumber(Integer.parseInt(m_sbCollectItem.toString()));
		}
		// </TSLType>
		if(tag.equals("TSLType")) {
			if(m_si != null)
				m_si.setType(m_sbCollectItem.toString());
		}
		// </Name>
		if(tag.equals("Name")) {
			if(m_mls != null)
				m_mls.setValue(m_sbCollectItem.toString());
			m_mls = null;
		}
		// </PostalAddress>
		if(tag.equals("PostalAddress")) {
			m_adr = null;
		}
		// </StreetAddress>
		if(tag.equals("StreetAddress")) {
			if(m_adr != null)
				m_adr.setStreetAddress(m_sbCollectItem.toString());
		}
		// </Locality>
		if(tag.equals("Locality")) {
			if(m_adr != null)
				m_adr.setLocality(m_sbCollectItem.toString());
		}
		// </PostalCode>
		if(tag.equals("PostalCode")) {
			if(m_adr != null)
				m_adr.setPostalCode(m_sbCollectItem.toString());
		}
		// </CountryName>
		if(tag.equals("CountryName")) {
			if(m_adr != null)
				m_adr.setCountryName(m_sbCollectItem.toString());
		}
		// </URI>
		if(tag.equals("URI")) {
			if(m_mls != null)
				m_mls.setValue(m_sbCollectItem.toString());
			m_mls = null;
		}
		// </TSLLegalNotice>
		if(tag.equals("TSLLegalNotice")) {
			if(m_mls != null)
				m_mls.setValue(m_sbCollectItem.toString());
			m_mls = null;
		}
		// </StatusDeterminationApproach>
		if(tag.equals("StatusDeterminationApproach")) {
			if(m_si != null)
				m_si.setStatusDeterminationApproach(m_sbCollectItem.toString());
		}
		// </SchemeTerritory>
		if(tag.equals("SchemeTerritory")) {
			if(m_si != null)
				m_si.setSchemeTerritory(m_sbCollectItem.toString());
		}
		// </HistoricalInformationPeriod>
		if(tag.equals("HistoricalInformationPeriod")) {
			if(m_si != null)
				m_si.setHistoricalInformationPeriod(Integer.parseInt(m_sbCollectItem.toString()));
		}
		// </ListIssueDateTime>
		if(tag.equals("ListIssueDateTime")) {
			if(m_si != null)
				m_si.setListIssueDate(ConvertUtils.str2date(m_sbCollectItem.toString()));
		}
		// </dateTime>
		if(tag.equals("dateTime")) {
			if(m_si != null && findTagOnStack("NextUpdate"))
				m_si.addNextUpdate(ConvertUtils.str2date(m_sbCollectItem.toString()));
		}
		// </ServiceTypeIdentifier>
		if(tag.equals("ServiceTypeIdentifier")) {
			if(m_tsps != null)
				m_tsps.setType(m_sbCollectItem.toString());
		}
		// </X509Certificate>
		if(tag.equals("X509Certificate")) {
			try {
			  if(m_tsps != null && findTagOnStack("ServiceDigitalIdentity")) {
				  X509Certificate cert = SignedDoc.readCertificate(Base64Util.decode(m_sbCollectItem.toString()));
				  if(cert != null) {
					  m_tsps.addCertificate(cert);
					  String sDn = ConvertUtils.convX509Name(cert.getIssuerX500Principal());
					  String sCn = ConvertUtils.getCommonName(sDn);
					  if(m_logger.isDebugEnabled())
						  m_logger.debug("DN: " + sDn + " CN: " + sCn);
					  m_tsps.setCaCn(sCn);
				  }
			  }
			} catch(DigiDocException ex) {
				SAXDigiDocException.handleException(ex);
			}
		}
		// </X509SubjectName>
		if(tag.equals("X509SubjectName")) {
			if(m_tsps != null && findTagOnStack("ServiceDigitalIdentity"))
				m_tsps.addSubjectName(new MultiLangString(null, m_sbCollectItem.toString()));
			if(m_tsps != null && findTagOnStack("DigitalId")) {
				m_tsps.addSubjectName(new MultiLangString(null, m_sbCollectItem.toString()));
				String cn = ConvertUtils.getCommonName(m_sbCollectItem.toString());
				if(cn != null && cn.trim().length() > 0)
					m_tsps.setCn(cn);
			}
		}
		// </ServiceStatus>
		if(tag.equals("ServiceStatus")) {
			if(m_tsps != null)
				m_tsps.setStatus(m_sbCollectItem.toString());
		}
		// </StatusStartingTime>
		if(tag.equals("StatusStartingTime")) {
			if(m_tsps != null)
				m_tsps.setStatusStartingTime(ConvertUtils.str2date(m_sbCollectItem.toString()));
		}
		// </QualityName>
		if(tag.equals("QualityName")) {
			if(m_qual != null)
				m_qual.setName(m_sbCollectItem.toString());
		}
		// </QualityValue>
		if(tag.equals("QualityValue")) {
			if(m_qual != null)
				m_qual.setValue(Integer.parseInt(m_sbCollectItem.toString()));
		}
		// </ServiceSupplyPoint>
		if(tag.equals("ServiceSupplyPoint")) {
			if(m_tsp != null)
				m_tsps.addServiceAccessPoint(m_sbCollectItem.toString());
		}
		
		// </QualityElement>
		if(tag.equals("QualityElement")) 
			m_qual = null;
		// </TSPService>
		if(tag.equals("TSPService")) 
			m_tsps = null;
		// </TrustServiceProvider>
		if(tag.equals("TrustServiceProvider"))
			m_tsp = null;
		m_sbCollectItem = null;
	}
	
	/**
	 * SAX characters event handler
	 * @param buf received bytes array
	 * @param offset offset to the array
	 * @param len length of data
	 */
	public void characters(char buf[], int offset, int len)
		throws SAXException 
    {
		String s = new String(buf, offset, len);
        if(s != null && m_sbCollectItem != null)
			    m_sbCollectItem.append(s);
	}
	
}
