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

import com.sun.xml.internal.ws.api.message.Packet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.wso2.security.tools.scanner.QualysScannerConstants;
import org.wso2.security.tools.scanner.ScannerConstants;
import org.wso2.security.tools.scanner.config.QualysScannerParam;
import org.wso2.security.tools.scanner.config.ScanContext;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.scanner.QualysScanner;
import org.wso2.security.tools.scanner.utils.CallbackUtil;
import org.wso2.security.tools.scanner.utils.RequestBodyBuilder;
import org.wso2.security.tools.scanner.utils.ScanStatus;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.List;
import java.util.Map;
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
        log.info("INITIALIZING QUALYS SCANNER");
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
     * @param fileMap Map that contains the file paths.
     * @param appID   Application ID
     * @param jobID   Job ID
     * @param appName Web Application Name
     * @param host    host url of qualys
     * @return Authentication script id
     * @throws ScannerException Error occurred while adding authentication scripts
     */
    public String prepareScan(String appID, String jobID, String appName, Map<String, List<String>> fileMap,
            String host) throws ScannerException {
        String authScriptId = null;
        try {
            if (qualysApiInvoker.purgeScan(host, appID)) {
                String message = "Purge Application Successfully:  " + appID;
                CallbackUtil.persistScanLog(jobID, message, ScannerConstants.INFO);
            }
        } catch (IOException e) {
            String message = "Failed to purge application:  " + appID;
            CallbackUtil.persistScanLog(jobID, message, ScannerConstants.ERROR);
            throw new ScannerException("Error occurred while purging the Application Scan", e);
        }

        try {
            //Only one authentication script can be given per single scan.
            String addAuthRecordRequestBody = RequestBodyBuilder.buildAddAuthScriptRequestBody(appID,
                    fileMap.get(QualysScannerConstants.AUTHENTICATION_SCRIPTS).get(0));
            authScriptId = qualysApiInvoker.addAuthenticationScript(host, addAuthRecordRequestBody);
            String message = "Web Authentication Record is created :" + authScriptId;
            // CallbackUtil.persistScanLog(jobId, message, ScannerConstants.INFO);
            log.info(message);
        } catch (TransformerException | IOException | ParserConfigurationException | SAXException e) {
            throw new ScannerException("Error occurred while adding the authentication scripts ", e);
        }
        String updateWebAppRequestBody;
        try {
            updateWebAppRequestBody = RequestBodyBuilder.buildUpdateWebAppRequestBody(appName, authScriptId);
            String updatedWebId = qualysApiInvoker.updateWebApp(host, updateWebAppRequestBody, appID);
            if (updatedWebId.equalsIgnoreCase(updatedWebId)) {
                String message = "Newly added authentication script is added to web application : " + updatedWebId;
                log.info(message);
                //                CallbackUtil.persistScanLog(jobId, message, ScannerConstants.INFO);
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
     * @param scanContext Object that contains the scanner specific parameters.
     * @param host        host url of qualys
     * @return Scanner scan Id
     * @throws ScannerException Invalid parameters for authentication scripts
     */
    public String launchScan(ScanContext scanContext, String host) throws ScannerException {
        String launchScanRequestBody;
        String scannerScanId;
        try {
            launchScanRequestBody = RequestBodyBuilder.buildLaunchScanRequestBody(scanContext);
            scannerScanId = qualysApiInvoker.launchScan(host, launchScanRequestBody);
            if (scannerScanId != null) {
                scanContext.setScannerScanId(scannerScanId);
                String message = "Qualys Scan for " + scanContext.getWebAppName() + " has successfully submitted : "
                        + scannerScanId;
                //                        CallbackUtil
                //                                .updateScanStatus(scannerRequest.getJobId(), ScanStatus.SUBMITTED, null, scannerScanId);
                //                        CallbackUtil.persistScanLog(scannerRequest.getJobId(), message, ScannerConstants.INFO);
                log.error(message);
                StatusChecker statusChecker = new StatusChecker(qualysApiInvoker, scanContext, 1, 1);
                statusChecker.activateStatusChecker();
            }
        } catch (ParserConfigurationException | TransformerException | SAXException | IOException e) {
            throw new ScannerException("Error occurred while launching the scan", e);
        }
        return scannerScanId;
    }

    public void calcelScan(String host, String scanId, String jobId) throws ScannerException {
        try {
            String status = qualysApiInvoker.retrieveStatus(host, scanId);
            if ((status.equalsIgnoreCase(QualysScannerConstants.RUNNING)) || status
                    .equalsIgnoreCase(QualysScannerConstants.SUBMITTED)) {
                if (qualysApiInvoker.cancelScan(host, scanId)) {
                    String message = "Scan id : " + scanId + " got cancelled as per request. ";
                    CallbackUtil.updateScanStatus(jobId, ScanStatus.CANCELED, null, scanId);
                    CallbackUtil.persistScanLog(jobId, message, ScannerConstants.INFO);
                } else {
                    String message = "Could not cancel scan : " + scanId;
                    CallbackUtil.updateScanStatus(jobId, ScanStatus.ERROR, null, scanId);
                    CallbackUtil.persistScanLog(jobId, message, ScannerConstants.ERROR);
                }
            } else {
                String message = "Could not find active scan for scanId : " + scanId;
                CallbackUtil.updateScanStatus(jobId, ScanStatus.ERROR, null, scanId);
                CallbackUtil.persistScanLog(jobId, message, ScannerConstants.ERROR);
            }
        } catch (SAXException | ParserConfigurationException | IOException e) {
            throw new ScannerException("Could not cancel scan : " + scanId, e);
        }
    }
}
