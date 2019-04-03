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
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.security.tools.scanner.QualysScannerConstants;
import org.wso2.security.tools.scanner.ScannerConstants;
import org.wso2.security.tools.scanner.config.ConfigurationReader;
import org.wso2.security.tools.scanner.config.QualysScannerParam;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.handler.QualysApiInvoker;
import org.wso2.security.tools.scanner.handler.QualysScanHandler;
import org.wso2.security.tools.scanner.handler.StatusChecker;
import org.wso2.security.tools.scanner.utils.CallbackUtil;
import org.wso2.security.tools.scanner.utils.ErrorMessage;
import org.wso2.security.tools.scanner.utils.ScanStatus;
import org.wso2.security.tools.scanner.utils.ScannerRequest;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.FileNotFoundException;
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
 * This class is responsible to initiate the generic use cases of Qualys scanner
 */
@Component("QualysScanner") public class QualysScanner extends AbstractScanner {
    private final Log log = LogFactory.getLog(QualysScanner.class);
    public static String host;
    private QualysScannerParam qualysScannerParam;
    private QualysScanHandler qualysScanHandler;

    @Override public void init() {
        try {
            ConfigurationReader.loadConfiguration();
            host = ConfigurationReader.getConfigProperty(QualysScannerConstants.HOST);
            QualysApiInvoker qualysApiInvoker = new QualysApiInvoker();
            qualysApiInvoker.setBasicAuth(setCredentials());
            this.qualysScanHandler = new QualysScanHandler(qualysApiInvoker);
            qualysScanHandler.initiateQualysScanner(host);
        } catch (ScannerException e) {
            log.error("Failed to initiate Qualys Scanner. ", e);
        } catch (FileNotFoundException e) {
            log.error("Failed to initiate Qualys Scanner.Configuration file is not provided", e);
        }
    }

    @Override public ResponseEntity startScan(ScannerRequest scannerRequest) {
        ResponseEntity responseEntity = null;
        String authScriptId;
        String scannerScanId;
        if (!StringUtils.isEmpty(scannerRequest.getProductName())) {
            if (scannerRequest.getFileMap().get("authenticationScripts").size() != 0) {
                try {
                    if (!setQualysScannerParam(scannerRequest)) {
                        String message = "Error occurred while submitting the start scan request since "
                                + "given application is not available : " + scannerRequest.getProductName();
                        responseEntity = new ResponseEntity<>(new ErrorMessage(HttpStatus.BAD_REQUEST.value(), message),
                                HttpStatus.BAD_REQUEST);
                        return responseEntity;
                    }
                    authScriptId = qualysScanHandler.prepareScan(scannerRequest.getJobId(), qualysScannerParam, host);
                    scannerScanId = qualysScanHandler.launchScan(qualysScannerParam, authScriptId, host);
                    if (scannerScanId != null) {
                        String message = "Qualys Scan for " + qualysScannerParam.getWebAppName()
                                + " has successfully submitted : " + scannerScanId;
                        //                        CallbackUtil
                        //                                .updateScanStatus(scannerRequest.getJobId(), ScanStatus.SUBMITTED, null, scannerScanId);
                        //                        CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.INFO);
                        log.error(message);
                        responseEntity = new ResponseEntity<>(HttpStatus.ACCEPTED);
                        StatusChecker statusChecker = new StatusChecker(qualysScanHandler.getQualysApiInvoker(),
                                scannerScanId, scannerRequest.getJobId(), 1, 1);
                        statusChecker.activateStatusChecker();
                    }
                } catch (InvalidRequestException e) {
                    String message = "Failed to start scan " + scannerRequest.getProductName() + " due to invalid "
                            + "parameters : " + e.getMessage();
                    responseEntity = new ResponseEntity<>(new ErrorMessage(HttpStatus.BAD_REQUEST.value(), message),
                            HttpStatus.BAD_REQUEST);
                    CallbackUtil.updateScanStatus(scannerRequest.getJobId(), ScanStatus.ERROR, null, null);
                    CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.ERROR);
                } catch (ScannerException e) {
                    String message = "Failed to start scan " + scannerRequest.getProductName() + " due to invalid "
                            + "parameters : " + e.getMessage();
                    //                    CallbackUtil.updateScanStatus(scannerRequest.getJobId(), ScanStatus.ERROR, null, null);
                    //                    CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.ERROR);
                    log.error(message);
                }
            } else {
                String message = "Error occurred while submitting the start scan request since "
                        + "the authentication script is not provided. ";
                responseEntity = new ResponseEntity<>(
                        new ErrorMessage(HttpStatus.INTERNAL_SERVER_ERROR.value(), message),
                        HttpStatus.INTERNAL_SERVER_ERROR);
                log.error(message);
                //                CallbackUtil.updateScanStatus(scannerRequest.getJobId(), ScanStatus.ERROR, null, null);
                //                CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.ERROR);
            }
        }
        return responseEntity;
    }

    @Override public ResponseEntity cancelScan(ScannerRequest scannerRequest) {
        return null;
    }

    /**
     * Create QualysScannerParam object which contains the parameters related to Qualys scanner.
     *
     * @param scannerRequest scanner request
     * @throws InvalidRequestException Invalid request error
     */
    private Boolean setQualysScannerParam(ScannerRequest scannerRequest) throws InvalidRequestException {
        Map<String, List<String>> fileMap = scannerRequest.getFileMap();
        Map<String, List<String>> parameterMap = scannerRequest.getParameterMap();
        this.qualysScannerParam = new QualysScannerParam();
        qualysScannerParam.setScanName(
                QualysScannerConstants.QUALYS_SCAN_NAME_PREFIX + scannerRequest.getProductName() + " " + getDate());
        try {

            qualysScannerParam.setWebAppName(scannerRequest.getProductName());
            qualysScannerParam.setWebAppId(
                    getIdForGivenTag(QualysScannerConstants.QUALYS_WEB_APPLICATION_LIST_FILE_PATH,
                            QualysScannerConstants.QUALYS_WEBAPP_TAG_NAME, scannerRequest.getProductName()));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new InvalidRequestException(
                    "Error occurred while retrieving the web app id from given product name :" + parameterMap
                            .get("productName").get(0), e);
        }

        if (StringUtils.isEmpty(qualysScannerParam.getWebAppId())) {
            return false;
        }

        if (parameterMap.containsKey(QualysScannerConstants.TYPE_KEYWORD)) {
            //Assuming the size of the list is one
            qualysScannerParam.setType(parameterMap.get(QualysScannerConstants.TYPE_KEYWORD).get(0));
        } else {
            qualysScannerParam.setType(ConfigurationReader.getConfigProperty(QualysScannerConstants.TYPE_KEYWORD));
        }

        if (parameterMap.containsKey(QualysScannerConstants.SCANNER_APPILIANCE_TYPE_KEYWORD)) {
            qualysScannerParam.setScannerApplianceType(
                    parameterMap.get(QualysScannerConstants.SCANNER_APPILIANCE_TYPE_KEYWORD).get(0));
        } else {
            qualysScannerParam.setScannerApplianceType(
                    ConfigurationReader.getConfigProperty(QualysScannerConstants.SCANNER_APPILIANCE_TYPE_KEYWORD));
        }

        if (parameterMap.containsKey(QualysScannerConstants.PROFILE_NAME_KEYWORD)) {
            try {
                qualysScannerParam.setProfileId(
                        getIdForGivenTag(QualysScannerConstants.QUALYS_OPTIONAL_PROFILE_LIST_FILE_PATH,
                                QualysScannerConstants.QUALYS_OPTIONAL_PROFILE_TAG_NAME,
                                parameterMap.get(QualysScannerConstants.PROFILE_NAME_KEYWORD).get(0)));
            } catch (ParserConfigurationException | SAXException | IOException e) {
                String message = "Error occurred in retrieving profile id for given profile :" + parameterMap
                        .get(QualysScannerConstants.PROFILE_NAME_KEYWORD).get(0)
                        + " ,since default profile will be used for the scan";
                log.error(message);
                //                CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.WARN);
                qualysScannerParam.setProfileId(
                        ConfigurationReader.getConfigProperty(QualysScannerConstants.PROFILE_NAME_KEYWORD));
            }
        } else {
            qualysScannerParam
                    .setProfileId(ConfigurationReader.getConfigProperty(QualysScannerConstants.PROFILE_NAME_KEYWORD));
        }

        if (Boolean.parseBoolean(parameterMap.get(QualysScannerConstants.PROGRESSIVE_SCAN).get(0))) {
            qualysScannerParam.setProgressiveScanning(QualysScannerConstants.ENABLED);
        } else {
            qualysScannerParam.setProgressiveScanning(QualysScannerConstants.DISABLED);
        }

        if (parameterMap.containsKey(QualysScannerConstants.EMAIL)) {
            qualysScannerParam.setEmail(parameterMap.get(QualysScannerConstants.EMAIL).get(0));
        }

        qualysScannerParam.setListOfAuthenticationScripts(fileMap.get(QualysScannerConstants.AUTHENTICATION_SCRIPTS));
        if (fileMap.containsKey(QualysScannerConstants.CRAWLINGSCRIPTS)) {
            qualysScannerParam.setListOfCrawlingScripts(fileMap.get(QualysScannerConstants.CRAWLINGSCRIPTS));
        }
        return true;
    }

    /**
     * Set credentials for the basic authorization.
     *
     * @return basic authentication base 64 encoded string
     * @throws ScannerException Error occurred while encoding the credentials.
     */
    private String setCredentials() throws ScannerException {
        String basicAuth;
        String qualysUsername = ConfigurationReader.getConfigProperty(QualysScannerConstants.USERNAME);
        String qualysPassword = ConfigurationReader.getConfigProperty(QualysScannerConstants.PASSWORD);
        String userPassword = qualysUsername + ":" + qualysPassword;
        try {
            basicAuth = new String(new Base64().encode(userPassword.getBytes()), "UTF-8");
            return basicAuth;
        } catch (UnsupportedEncodingException e) {
            throw new ScannerException("Qualys credentials could not be encoded\"", e);
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

    /**
     * Get value for given tag.
     *
     * @param filePath filePath file path of the list of data
     * @param tagName  tag name
     * @param name     Name
     * @return id
     * @throws ParserConfigurationException Error occurred while parsing
     * @throws IOException                  IOException
     * @throws SAXException                 Error occurred while parsing
     */
    private String getIdForGivenTag(String filePath, String tagName, String name)
            throws ParserConfigurationException, IOException, SAXException {
        File file = new File(filePath);
        String id = null;
        NodeList nodeList;
        DocumentBuilder builder;

        DocumentBuilderFactory dbFactory = getSecuredDocumentBuilderFactory();
        builder = dbFactory.newDocumentBuilder();
        Document doc = builder.parse(file);
        doc.getDocumentElement().normalize();

        nodeList = doc.getElementsByTagName(tagName);

        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);

            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) node;
                if (eElement.getElementsByTagName(QualysScannerConstants.NAME_KEYWORD).item(0).getTextContent()
                        .equals(name)) {
                    id = eElement.getElementsByTagName(QualysScannerConstants.ID_KEYWORD).item(0).getTextContent();
                }
            }
        }
        return id;
    }
}
