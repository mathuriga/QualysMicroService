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

package org.wso2.security.tools.scanner.scanner;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.security.tools.scanner.QualysScannerConstants;
import org.wso2.security.tools.scanner.config.ConfigurationReader;
import org.wso2.security.tools.scanner.config.QualysScannerParam;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.handler.QualysApiInvoker;
import org.wso2.security.tools.scanner.handler.QualysScanHandler;
import org.wso2.security.tools.scanner.handler.StatusChecker;
import org.wso2.security.tools.scanner.utils.ScannerRequest;
import org.wso2.security.tools.scanner.utils.ScannerResponse;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * This class is responsible to handle the generic use cases of Qualys scanner
 */
@Component("QualysScanner") public class QualysScanner extends AbstractScanner {
    private final Log log = LogFactory.getLog(QualysScanner.class);
    //    private String basicAuth = null;
    public static String host;
    private QualysScannerParam qualysScannerParam;
    QualysScanHandler qualysScanHandler;
    // TODO: 4/2/19 introduce atomic string to check status and decide how to handle

    @Override public void init() throws ScannerException {
        this.host = ConfigurationReader.getConfigProperty(QualysScannerConstants.HOST);
        QualysApiInvoker qualysApiInvoker = new QualysApiInvoker();
        qualysApiInvoker.setBasicAuth(setCredentials());
        this.qualysScanHandler = new QualysScanHandler(qualysApiInvoker);
        qualysScanHandler.initiateQualysScanner(host);
    }

    @Override public ScannerResponse startScan(ScannerRequest scannerRequest)
            throws InvalidRequestException, ScannerException {
        setQualysScannerParam(scannerRequest);
        String authScriptId = null;
        authScriptId = qualysScanHandler.prepareScan(qualysScannerParam, host);
        ScannerResponse scannerResponse = qualysScanHandler.launchScan(qualysScannerParam, authScriptId, host);
        //TODO validation of file path

        StatusChecker statusChecker = new StatusChecker(qualysScanHandler.getQualysApiInvoker(),
                scannerResponse.getScanID(), scannerRequest.getScanId(), 1, 1);
        statusChecker.activateStatusChecker();
        return scannerResponse;
    }

    @Override public ScannerResponse cancelScan(ScannerRequest scannerRequest) throws ScannerException {
        return null;
    }

    private QualysScannerParam setQualysScannerParam(ScannerRequest scannerRequest) throws ScannerException {
        Map<String, List<String>> fileMap = scannerRequest.getFileMap();
        Map<String, List<String>> parameterMap = scannerRequest.getParameterMap();
        this.qualysScannerParam = new QualysScannerParam();
        qualysScannerParam.setScanName(
                QualysScannerConstants.QUALYS_SCAN_NAME_PREFIX + scannerRequest.getProductName() + " " + getDate());

        qualysScannerParam.setWebAppName(scannerRequest.getProductName());
        try {
            qualysScannerParam.setWebAppId(
                    getIDforGivenTag(QualysScannerConstants.QUALYS_WEB_APPLICATION_LIST_FILE_PATH,
                            QualysScannerConstants.QUALYS_WEBAPP_TAG_NAME, scannerRequest.getProductName()));
        } catch (ParserConfigurationException e) {
            throw new ScannerException(
                    "Error occured while retrieivng the web app id from given product name :" + parameterMap
                            .get("productName").get(0), e);
        }
        if (parameterMap.containsKey("type")) {
            //Assuming the size of the list is one
            qualysScannerParam.setType(parameterMap.get("type").get(0));
        } else {
            qualysScannerParam.setType(ConfigurationReader.getConfigProperty("type"));
        }

        if (parameterMap.containsKey("scannerApplianceType")) {
            qualysScannerParam.setScannerApplianceType(parameterMap.get("scannerApplianceType").get(0));
        } else {
            qualysScannerParam.setScannerApplianceType(ConfigurationReader.getConfigProperty("scannerApplianceType"));
        }

        qualysScannerParam
                .setWebAuthRecordDefault(Boolean.parseBoolean(parameterMap.get("isWebAuthRecordDefault").get(0)));

        if (parameterMap.containsKey("profileName")) {
            try {
                qualysScannerParam.setProfileId(
                        getIDforGivenTag(QualysScannerConstants.QUALYS_OPTIONAL_PROFILE_LIST_FILE_PATH,
                                QualysScannerConstants.QUALYS_OPTIONAL_PROFILE_TAG_NAME,
                                parameterMap.get("profileName").get(0)));
            } catch (ParserConfigurationException e) {
                log.warn("Error occurred in retrieving profile id for given profile :" + parameterMap.get("profileName")
                        .get(0) + " ,since default profile will be used for the scan");
                qualysScannerParam.setProfileId(Integer.parseInt(ConfigurationReader.getConfigProperty("profileName")));
            }
        } else {
            qualysScannerParam.setProfileId(Integer.parseInt(ConfigurationReader.getConfigProperty("profileName")));
        }

        qualysScannerParam.setIsProgressinveScanningEnabled(parameterMap.get("isProgressiveScanningEnabled").get(0));

        if (parameterMap.containsKey("email")) {
            qualysScannerParam.setEmail(parameterMap.get("email").get(0));
        }

        qualysScannerParam.setListOfAuthenticationScripts(fileMap.get("authenticationScripts"));
        qualysScannerParam.setListOfCrawlingScripts(fileMap.get("authenticationScripts"));
        return qualysScannerParam;
    }

    /**
     * Set credentials for the basic authorization.
     *
     * @return basic authentication base 64 encoded string
     * @throws ScannerException
     */
    private String setCredentials() throws ScannerException {
        String basicAuth;
        String qualysUsername = ConfigurationReader.getConfigProperty(QualysScannerConstants.USERNAME);
        String qualysPassword = ConfigurationReader.getConfigProperty(QualysScannerConstants.PASSWORD);
        String userpass = qualysUsername + ":" + qualysPassword;
        try {
            basicAuth = new String(new Base64().encode(userpass.getBytes()), "UTF-8");
            return basicAuth;
        } catch (UnsupportedEncodingException e) {
            throw new ScannerException("Credential could not be encoded\"", e);
        }
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

    private Integer getIDforGivenTag(String filePath, String tagName, String name)
            throws ScannerException, ParserConfigurationException {
        File file = new File(filePath);
        String id = null;
        NodeList nodeList;
        DocumentBuilder builder;

        DocumentBuilderFactory dbFactory = getSecuredDocumentBuilderFactory();

        try {
            builder = dbFactory.newDocumentBuilder();
            Document doc = builder.parse(file);
            doc.getDocumentElement().normalize();

            nodeList = doc.getElementsByTagName(tagName);

            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);

                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) node;
                    //                    log.info("name in xml:"+eElement.getElementsByTagName("name"));
                    //                    log.info("productname"+productName);

                    if (eElement.getElementsByTagName(QualysScannerConstants.NAME_KEYWORD).item(0).getTextContent()
                            .equals(name)) {
                        id = eElement.getElementsByTagName(QualysScannerConstants.ID_KEYWORD).item(0).getTextContent();
                    }
                }
            }
            return Integer.parseInt(id);

        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new ScannerException("Error while retrieving the ID!", e);
        }

    }

}
