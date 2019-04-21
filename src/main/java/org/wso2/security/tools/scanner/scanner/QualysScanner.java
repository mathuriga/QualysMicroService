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

import com.sun.org.apache.xpath.internal.operations.Bool;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.EnumUtils;
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
import org.wso2.security.tools.scanner.config.ScanContext;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.handler.QualysApiInvoker;
import org.wso2.security.tools.scanner.handler.QualysScanHandler;
import org.wso2.security.tools.scanner.handler.StatusChecker;
import org.wso2.security.tools.scanner.utils.CallbackUtil;
import org.wso2.security.tools.scanner.utils.ErrorMessage;
import org.wso2.security.tools.scanner.utils.QualysPropertyEnums;
import org.wso2.security.tools.scanner.utils.ScanStatus;
import org.wso2.security.tools.scanner.utils.ScannerRequest;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
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
    private ScanContext scanContext;

    @Override public void init() {
        try {
            ConfigurationReader.loadConfiguration();
            host = ConfigurationReader.getConfigProperty(QualysScannerConstants.HOST);
            QualysApiInvoker qualysApiInvoker = new QualysApiInvoker();
            qualysApiInvoker.setBasicAuth(setCredentials());
            this.qualysScanHandler = new QualysScanHandler(qualysApiInvoker);
            // TODO: 4/3/19 remove this 
            //            qualysScanHandler.initiateQualysScanner(host);
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
        try {
            if (validateParameters(scannerRequest)) {
                authScriptId = qualysScanHandler.prepareScan(scannerRequest.getAppId(), scannerRequest.getJobId(),
                        scannerRequest.getParameterMap().get(QualysScannerConstants.QUALYS_WEBAPP_TAG_NAME).get(0),
                        scannerRequest.getFileMap(), host);
                ScanContext scanContext = new ScanContext();
                scanContext.setJobID(scannerRequest.getJobId());
                scanContext.setWebAppId(scannerRequest.getAppId());
                scanContext.setAuthId(authScriptId);
                scanContext.setProfileId(
                        scannerRequest.getParameterMap().get(QualysScannerConstants.PROFILE_NAME_KEYWORD).get(0));
                scanContext.setType(scannerRequest.getParameterMap().get(QualysScannerConstants.TYPE_KEYWORD).get(0));
                scanContext.setScannerApplianceType(
                        scannerRequest.getParameterMap().get(QualysScannerConstants.SCANNER_APPILIANCE_TYPE_KEYWORD)
                                .get(0));
                if (Boolean.parseBoolean(
                        scannerRequest.getParameterMap().get(QualysScannerConstants.PROGRESSIVE_SCAN).get(0))) {
                    scanContext.setProgressiveScanning(QualysScannerConstants.ENABLED);
                } else {
                    scanContext.setProgressiveScanning(QualysScannerConstants.DISABLED);
                }

                scannerScanId = qualysScanHandler.launchScan(scanContext, host);

                if (scannerScanId != null) {
                    responseEntity = new ResponseEntity<>(HttpStatus.ACCEPTED);
                }
            }

        } catch (ScannerException e) {
            String message =
                    "Failed to start scan " + scannerRequest.getProductName() + " due to invalid " + "parameters : " + e
                            .getMessage();
            responseEntity = new ResponseEntity<>(new ErrorMessage(HttpStatus.INTERNAL_SERVER_ERROR.value(), message),
                    HttpStatus.INTERNAL_SERVER_ERROR);
            //                    CallbackUtil.updateScanStatus(scannerRequest.getJobId(), ScanStatus.ERROR, null, null);
            //                    CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.ERROR);
            log.error(message);
        } catch (InvalidRequestException e) {
            String message = "Error occurred while submitting the start scan request since "
                    + "given application is not available : " + scannerRequest.getAppId();

            CallbackUtil.updateScanStatus(scannerRequest.getJobId(), ScanStatus.ERROR, null, null);
            CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.ERROR);
            responseEntity = new ResponseEntity<>(new ErrorMessage(HttpStatus.BAD_REQUEST.value(), message),
                    HttpStatus.BAD_REQUEST);
        }
        return responseEntity;
    }

    @Override public ResponseEntity cancelScan(ScannerRequest scannerRequest) {
        ResponseEntity responseEntity = null;
        try {
            qualysScanHandler.calcelScan(host, scannerRequest.getJobId(), "");
            responseEntity = new ResponseEntity<>(new ErrorMessage(HttpStatus.ACCEPTED.value(), "Scan is cancelled"),
                    HttpStatus.ACCEPTED);
        } catch (ScannerException e) {
            String message = "Error occurred while cancelling scan : " + scannerRequest.getAppId();

            CallbackUtil.updateScanStatus(scannerRequest.getJobId(), ScanStatus.ERROR, null, null);
            CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.ERROR);
            responseEntity = new ResponseEntity<>(new ErrorMessage(HttpStatus.INTERNAL_SERVER_ERROR.value(), message),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return responseEntity;
    }

    private Boolean validateParameters(ScannerRequest scannerRequest) throws InvalidRequestException {
        String errorMessage = null;
        if (!StringUtils.isEmpty(scannerRequest.getAppId()) && !scannerRequest.getAppId()
                .matches(QualysScannerConstants.INTEGER_REGEX)) {
            errorMessage = "Application Id is not provided or Invalid Application ID";
            throw new InvalidRequestException(errorMessage);
        }

        Map<String, List<String>> parameterMap = scannerRequest.getParameterMap();

        if (!StringUtils.isEmpty(parameterMap.get(QualysScannerConstants.PROFILE_ID).get(0)) && !scannerRequest
                .getAppId().matches(QualysScannerConstants.INTEGER_REGEX)) {
            errorMessage = "Profile Id is not provided or Invalid Profile Id";
            throw new InvalidRequestException(errorMessage);
        }

        if (!EnumUtils.isValidEnum(QualysPropertyEnums.ScannerApplianceType.class,
                parameterMap.get(QualysScannerConstants.SCANNER_APPILIANCE).get(0))) {
            errorMessage = "Scanner Appliance Type is not provided or invalid";
            throw new InvalidRequestException(errorMessage);
        }

        if (!EnumUtils.isValidEnum(QualysPropertyEnums.Type.class,
                parameterMap.get(QualysScannerConstants.TYPE_KEYWORD).get(0))) {
            errorMessage = "Type of the scan is not provided or invalid";
            throw new InvalidRequestException(errorMessage);
        }

        List<String> authFiles = scannerRequest.getFileMap().get(QualysScannerConstants.AUTHENTICATION_SCRIPTS);
        if (authFiles.size() != 0) {
            for (int i = 0; i < authFiles.size(); i++) {
                File file = new File(authFiles.get(0));
                if (!file.exists()) {
                    errorMessage = "Authentication script is not exists";
                    throw new InvalidRequestException(errorMessage);
                } else {
                    if (!file.getName().endsWith(QualysScannerConstants.XML)) {
                        errorMessage = "Invalid file type for Authentication Script";
                        throw new InvalidRequestException(errorMessage);
                    }
                }
            }
            errorMessage = "Authentication script is not provided";
            throw new InvalidRequestException(errorMessage);
        }

        return true;
    }

    /**
     * Set credentials for the basic authorization.
     *
     * @return basic authentication base 64 encoded string
     * @throws ScannerException Error occurred while encoding the credentials.
     */
    private char[] setCredentials() throws ScannerException {
        char[] basicAuth;
        // TODO: 4/3/19 change it to char 
        char[] qualysUsername = ConfigurationReader.getConfigProperty(QualysScannerConstants.USERNAME).toCharArray();
        char[] qualysPassword = ConfigurationReader.getConfigProperty(QualysScannerConstants.PASSWORD).toCharArray();
        // TODO: 4/3/19 rename

        String credential = Arrays.toString(qualysUsername) + ":" + Arrays.toString(qualysPassword);
        try {
            basicAuth = new String(new Base64().encode(credential.getBytes()), "UTF-8").toCharArray();
            Arrays.fill(qualysUsername, '0');
            Arrays.fill(qualysPassword, '0');
        } catch (UnsupportedEncodingException e) {
            throw new ScannerException("Qualys credentials could not be encoded\"", e);
        }
        return basicAuth;
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
