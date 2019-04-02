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

package org.wso2.security.tools.scanner.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.security.tools.scanner.QualysScannerConstants;
import org.wso2.security.tools.scanner.ScannerConstants;
import org.wso2.security.tools.scanner.config.QualysScannerParam;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.utils.CallbackUtil;
import org.wso2.security.tools.scanner.utils.RequestBodyBuilder;
import org.xml.sax.SAXException;

import java.io.IOException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

/**
 * This class is responsible to handle the required  use cases of Qualys scanner.
 */
public class QualysScanHandler {

    private final Log log = LogFactory.getLog(QualysScanHandler.class);
    private QualysApiInvoker qualysApiInvoker;

    public QualysScanHandler(QualysApiInvoker qualysApiInvoker) {
        this.qualysApiInvoker = qualysApiInvoker;
    }

    public QualysApiInvoker getQualysApiInvoker() {
        return qualysApiInvoker;
    }

    /**
     * This method used to initiate the Qualys scanner when the qualys scanner is launched first time. All the
     * prerequisite files will be created during this method execution.
     *
     * @param host Qualys scanner host endpoint.
     * @throws ScannerException It wraps the exceptions while creating the prerequisite files.
     */
    public void initiateQualysScanner(String host) throws ScannerException {

        log.info("STARTING QUALYS SCANNER");
        // Generate a file which contains the list of web apps in qualys scan
        qualysApiInvoker.generatePrerequisiteFile(host.concat(QualysScannerConstants.QUALYS_GET_APPLICATION_API),
                QualysScannerConstants.QUALYS_WEB_APPLICATION_LIST_FILE_PATH);
        log.info("Web Application list file is generated : "
                + QualysScannerConstants.QUALYS_WEB_APPLICATION_LIST_FILE_PATH);
        // Generate a file which contains the list of authentication scripts in qualys scan
        qualysApiInvoker
                .generatePrerequisiteFile(host.concat(QualysScannerConstants.QUALYS_GET_AUTHENTICATION_SCRIPT_API),
                        QualysScannerConstants.QUALYS_AUTHENTICATION_LIST_FILE_PATH);
        log.info("Authentication list file is generated : "
                + QualysScannerConstants.QUALYS_AUTHENTICATION_LIST_FILE_PATH);
        // Generate a file which contains the list of profiles in qualys scan
        qualysApiInvoker.generatePrerequisiteFile(host.concat(QualysScannerConstants.QUALYS_GET_OPTIONAL_PROFILE_API),
                QualysScannerConstants.QUALYS_OPTIONAL_PROFILE_LIST_FILE_PATH);
        log.info("Optional profile list file is generated : "
                + QualysScannerConstants.QUALYS_OPTIONAL_PROFILE_LIST_FILE_PATH);

    }

    /**
     * Prepare the scan before launching the scan. Main tasks are Adding the authentication scripts and crawling scripts.
     *
     * @param qualysScannerParam Object that contains the scanner specific parameters.
     * @param host               host url of qualys
     * @return Authentication script id
     * @throws ScannerException        Error occurred while adding authentication scripts
     * @throws InvalidRequestException Invalid parameters for authentication scripts
     */
    public String prepareScan(String jobId, QualysScannerParam qualysScannerParam, String host)
            throws ScannerException, InvalidRequestException {

        String authScriptId = null;
        try {
            if (qualysScannerParam.getListOfAuthenticationScripts().size() != 0) {
                String addAuthRecordRequestBody = RequestBodyBuilder
                        .buildAddAuthScriptRequestBody(qualysScannerParam.getWebAppName(),
                                qualysScannerParam.getListOfAuthenticationScripts());
                authScriptId = qualysApiInvoker.addAuthenticationScript(host, addAuthRecordRequestBody);
                String message = "Web Authentication Record is created :" + authScriptId;
                CallbackUtil.persistScanLog(jobId, message, ScannerConstants.INFO);
            }
        } catch (TransformerException | IOException | ParserConfigurationException | SAXException e) {
            throw new ScannerException("Error occurred while adding the authentication scripts ", e);
        }

        String updateWebAppRequestBody;
        try {
            updateWebAppRequestBody = RequestBodyBuilder
                    .updateWebAppRequestBody(qualysScannerParam.getWebAppName(), authScriptId);
            String updatedWebId = qualysApiInvoker
                    .updateWebApp(host, updateWebAppRequestBody, qualysScannerParam.getWebAppId());
            if (updatedWebId.equalsIgnoreCase(qualysScannerParam.getWebAppId())) {
                String message = "Newly added authentication script is added to web application : " + qualysScannerParam
                        .getWebAppId();
                CallbackUtil.persistScanLog(jobId, message, ScannerConstants.INFO);
            }
        } catch (ParserConfigurationException | TransformerException | SAXException | IOException e) {
            throw new ScannerException(
                    "Error occurred while updating the web app of Qualys with given authentication script", e);
        }
        return authScriptId;
    }

    /**
     * Launching the scan in qualys end
     *
     * @param qualysScannerParam Object that contains the scanner specific parameters.
     * @param authScriptId       Authentication Script Id
     * @param host               host url of qualys
     * @return Scanner scan Id
     * @throws InvalidRequestException Error occurred while adding authentication scripts
     * @throws ScannerException        Invalid parameters for authentication scripts
     */
    public String launchScan(QualysScannerParam qualysScannerParam, String authScriptId, String host)
            throws InvalidRequestException, ScannerException {
        String launchScanRequestBody;
        String scannerScanId;
        try {
            launchScanRequestBody = RequestBodyBuilder.buildLaunchScanRequestBody(qualysScannerParam, authScriptId);
            scannerScanId = qualysApiInvoker.launchScan(host, launchScanRequestBody);
        } catch (ParserConfigurationException | TransformerException | SAXException | IOException e) {
            throw new ScannerException("Error occurred while launching the scan", e);
        }
        return scannerScanId;
    }
}

