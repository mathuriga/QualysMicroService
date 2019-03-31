/*
 *
 *   Copyright (c) 2019, WSO2 Inc., WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package org.wso2.security.tools.scanner.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.security.tools.scanner.QualysScannerConstants;
import org.wso2.security.tools.scanner.config.ConfigurationReader;
import org.wso2.security.tools.scanner.config.QualysScannerParam;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.scanner.QualysScanner;
import org.wso2.security.tools.scanner.scanner.Scanner;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import static org.wso2.security.tools.scanner.scanner.AbstractScanner.getSecuredDocumentBuilderFactory;

/**
 * Qualys scanner accepts XML format request body which contains the data related for scan
 */
public class RequestBodyBuilder {
    private static final Log log = LogFactory.getLog(RequestBodyBuilder.class);

    public static String buildAddAuthScriptRequestBody(String appName, List<String> listOfAuthFiles)
            throws InvalidRequestException {

        String addAuthRecordRequestBody = null;

        try {
            DocumentBuilderFactory dbf = getSecuredDocumentBuilderFactory();
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.newDocument();

            Element root = doc.createElement("ServiceRequest");
            doc.appendChild(root);

            Element data = doc.createElement("data");
            root.appendChild(data);

            Element webAppAuthRecord = doc.createElement("WebAppAuthRecord");
            data.appendChild(webAppAuthRecord);

            File tempFile = new File(listOfAuthFiles.get(0));
            if (tempFile.exists()) {
                Element name = doc.createElement("name");
                name.appendChild(doc.createTextNode("Selenium Script for " + appName + " : " + getDate()));
                webAppAuthRecord.appendChild(name);
            } else {
                log.warn("Authentication script is not exist in " + tempFile.getAbsolutePath());
            }

            Element formRecord = doc.createElement("formRecord");
            webAppAuthRecord.appendChild(formRecord);

            Element type = doc.createElement("type");
            type.appendChild(doc.createTextNode("SELENIUM"));
            formRecord.appendChild(type);

            Element seleniumScript = doc.createElement("seleniumScript");
            formRecord.appendChild(seleniumScript);

            Element seleniumScriptName = doc.createElement("name");
            seleniumScriptName.appendChild(doc.createTextNode("SELENIUM"));
            seleniumScript.appendChild(seleniumScriptName);

            Element scriptData = doc.createElement("data");
            scriptData.appendChild(doc.createTextNode(getContentFromFile(tempFile.getAbsolutePath())));
            seleniumScript.appendChild(scriptData);

            Element regex = doc.createElement("regex");
            regex.appendChild(doc.createTextNode("selenium"));
            seleniumScript.appendChild(regex);

            StringWriter stringWriter = buildSecureStringWriter(doc);
            addAuthRecordRequestBody = stringWriter.getBuffer().toString();

            return addAuthRecordRequestBody;

        } catch (ParserConfigurationException e) {
            throw new InvalidRequestException("Error while parsing the XML request!", e);
        } catch (IOException e) {
            throw new InvalidRequestException("Error while reading selenium script!", e);
        } catch (TransformerException e) {
            throw new InvalidRequestException("Error while creating XML format request!", e);
        }

    }

    public static String updateWebAppRequestBody(String webAppName, String authId)
            throws InvalidRequestException {
        String updateWebAppRequestBody;
        try {
            DocumentBuilderFactory dbf = getSecuredDocumentBuilderFactory();
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.newDocument();
            Element root = doc.createElement("ServiceRequest");
            doc.appendChild(root);

            Element data = doc.createElement("data");
            root.appendChild(data);

            Element webApp = doc.createElement("WebApp");
            data.appendChild(webApp);

            Element name = doc.createElement("name");
            name.appendChild(doc.createTextNode(webAppName));
            webApp.appendChild(name);

            Element authRecords = doc.createElement("authRecords");
            webApp.appendChild(authRecords);

            Element add = doc.createElement("add");
            authRecords.appendChild(add);

            Element webAppAuthRecord = doc.createElement("WebAppAuthRecord");
            add.appendChild(webAppAuthRecord);

            Element id = doc.createElement("id");
            id.appendChild(doc.createTextNode(authId));
            webAppAuthRecord.appendChild(id);

            StringWriter stringWriter = buildSecureStringWriter(doc);
            updateWebAppRequestBody = stringWriter.getBuffer().toString();

            return updateWebAppRequestBody;

        } catch (ParserConfigurationException | TransformerException e) {
            throw new InvalidRequestException("Error while parsing the XML request!", e);
        }
    }

    public static String buildLaunchScanRequestBody(QualysScannerParam qualysScannerParam, String authScriptId) throws InvalidRequestException {
        String launchScanRequestBody = null;
        try {
            DocumentBuilderFactory dbf = getSecuredDocumentBuilderFactory();
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.newDocument();
            Element root = doc.createElement("ServiceRequest");
            doc.appendChild(root);

            Element data = doc.createElement("data");
            root.appendChild(data);

            Element wasScan = doc.createElement("WasScan");
            data.appendChild(wasScan);

            Element name = doc.createElement("name");
            name.appendChild(doc.createTextNode(qualysScannerParam.getScanName()));
            wasScan.appendChild(name);

            Element type = doc.createElement("type");
            type.appendChild(doc.createTextNode(qualysScannerParam.getType()));
            wasScan.appendChild(type);

            Element target = doc.createElement("target");
            wasScan.appendChild(target);

            Element webApp = doc.createElement("webApp");
            target.appendChild(webApp);

            Element webAppId = doc.createElement("id");
            webAppId.appendChild(doc.createTextNode(qualysScannerParam.getWebAppId().toString()));
            webApp.appendChild(webAppId);

            Element webAppAuthRecord = doc.createElement("webAppAuthRecord");
            target.appendChild(webAppAuthRecord);

            Element webAppAuthRecordId = doc.createElement("id");
            webAppAuthRecordId.appendChild(doc.createTextNode(authScriptId));
            webAppAuthRecord.appendChild(webAppAuthRecordId);

            Element scannerAppliance = doc.createElement("scannerAppliance");
            target.appendChild(scannerAppliance);

            Element scannerApplianceType = doc.createElement("type");
            scannerApplianceType.appendChild(doc.createTextNode(qualysScannerParam.getScannerApplianceType()));
            scannerAppliance.appendChild(scannerApplianceType);

            Element profile = doc.createElement("profile");
            wasScan.appendChild(profile);

            Element profileId = doc.createElement("id");
            profileId.appendChild(doc.createTextNode(qualysScannerParam.getProfileId().toString()));
            profile.appendChild(profileId);

            Element progressiveScanning = doc.createElement("progressiveScanning");
            progressiveScanning.appendChild(
                    doc.createTextNode(qualysScannerParam.getIsProgressinveScanningEnabled()));
            wasScan.appendChild(progressiveScanning);

            StringWriter stringWriter = buildSecureStringWriter(doc);
            launchScanRequestBody = stringWriter.getBuffer().toString();

            return launchScanRequestBody;
        } catch (ParserConfigurationException e) {
            throw new InvalidRequestException("Error while parsing the XML request!", e);
        } catch (TransformerException e) {
            throw new InvalidRequestException("Error while creating XML format request!", e);
        }

    }

    private static String getContentFromFile(String filePath) throws IOException {
        StringBuilder contentBuilder = new StringBuilder();

        try (Stream<String> stream = Files.lines(Paths.get(filePath), StandardCharsets.UTF_8)) {
            stream.forEach(s -> contentBuilder.append(s).append("\n"));
        }

        return contentBuilder.toString();
    }

    /**
     * Build a secure String writer.
     *
     * @param doc Document that needs to be converted to String
     * @return StringWriter
     * @throws ScannerException
     */
    private static StringWriter buildSecureStringWriter(Document doc) throws TransformerException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();

        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));

        return writer;
    }

    /**
     * Get the current date.
     *
     * @return formatted date and time
     */
    private static String getDate() {
        Date date = new Date();
        SimpleDateFormat ft = new SimpleDateFormat("E yyyy.MM.dd 'at' hh:mm:ss");

        return ft.format(date);
    }
}


