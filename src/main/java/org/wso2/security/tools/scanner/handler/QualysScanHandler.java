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
import org.wso2.security.tools.scanner.config.QualysScannerParam;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.scanner.QualysScanner;
import org.wso2.security.tools.scanner.utils.RequestBodyBuilder;
import org.wso2.security.tools.scanner.utils.ScannerResponse;

/**
 * TODO : Class level comment
 */
public class QualysScanHandler {
    private final Log log = LogFactory.getLog(QualysScanHandler.class);

    private QualysApiInvoker qualysApiInvoker = new QualysApiInvoker();

    public QualysScanHandler(QualysApiInvoker qualysApiInvoker) {
        this.qualysApiInvoker = qualysApiInvoker;
    }

    public QualysApiInvoker getQualysApiInvoker() {
        return qualysApiInvoker;
    }

    public void setQualysApiInvoker(QualysApiInvoker qualysApiInvoker) {
        this.qualysApiInvoker = qualysApiInvoker;
    }

    public void initiateQualysScanner(String host) throws ScannerException {
        qualysApiInvoker.generatePrerequestieFile(host.concat(QualysScannerConstants.QUALYS_GET_APPLICATION_API),
                QualysScannerConstants.QUALYS_WEB_APPLICATION_LIST_FILE_PATH);
        log.info("Web Application list is generated");
        qualysApiInvoker
                .generatePrerequestieFile(host.concat(QualysScannerConstants.QUALYS_GET_AUTHENTICATION_SCRIPT_API),
                        QualysScannerConstants.QUALYS_AUTHENTICATION_LIST_FILE_PATH);
        log.info("Authentication list is generated");
        qualysApiInvoker.generatePrerequestieFile(host.concat(QualysScannerConstants.QUALYS_GET_OPTIONAL_PROFILE_API),
                QualysScannerConstants.QUALYS_OPTIONAL_PROFILE_LIST_FILE_PATH);
        log.info("Optional file list is generated");
    }

    public String prepareScan(QualysScannerParam qualysScannerParam, String host)
            throws ScannerException, InvalidRequestException {
        // TODO: 3/31/19 check status 
        String authScriptId = null;
        if (qualysScannerParam.getListOfAuthenticationScripts().size() != 0) {
            String addAuthRecordRequestBody = RequestBodyBuilder
                    .buildAddAuthScriptRequestBody(qualysScannerParam.getWebAppName(),
                            qualysScannerParam.getListOfAuthenticationScripts());
            authScriptId = qualysApiInvoker.addAuthenticationScript(host, addAuthRecordRequestBody);
            log.info("Web Authentication Record is created :" + authScriptId);
        }

        if(authScriptId!=null) {

            String updateWebAppRequestBody = RequestBodyBuilder
                    .updateWebAppRequestBody(qualysScannerParam.getWebAppName(), authScriptId);
            String updatedWebId = qualysApiInvoker.updateWebApp(host, updateWebAppRequestBody,
                    qualysScannerParam.getWebAppId().toString());
            if (updatedWebId.equalsIgnoreCase(qualysScannerParam.getWebAppId().toString())) {
                log.info("Newly added authentication script is added to web application : " + qualysScannerParam.getWebAppId());
            }
        }
        return authScriptId;
    }

    public ScannerResponse launchScan(QualysScannerParam qualysScannerParam,String authScriptId,String host)
            throws InvalidRequestException, ScannerException {
        String launchScanRequestBody = RequestBodyBuilder
                .buildLaunchScanRequestBody(qualysScannerParam, authScriptId);
        log.info("launch request build");
        ScannerResponse scannerResponse = qualysApiInvoker.launchScan(host, launchScanRequestBody);
        log.info("SCAN ID : " + scannerResponse.getScanID());
        log.info("RESPONSE:" + Boolean.toString(scannerResponse.getIsSuccessful()));
        return scannerResponse;
    }
}

