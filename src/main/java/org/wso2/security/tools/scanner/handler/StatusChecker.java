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
import org.wso2.security.tools.scanner.ScannerConstants;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.scanner.QualysScanner;
import org.wso2.security.tools.scanner.utils.CallbackUtil;
import org.wso2.security.tools.scanner.utils.ScanStatus;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Responsible to check the scan status.
 */
public class StatusChecker {
    private static final Log log = LogFactory.getLog(StatusChecker.class);
    private static final int NUM_THREADS = 1;
    private ScheduledExecutorService scheduler;
    private final long initialDelay;
    private final long delayBetweenRuns;
    private static AtomicReference<String> currentStatus = new AtomicReference<>();
    private QualysApiInvoker qualysApiInvoker;
    private String qualysScanId;
    private String jobId;

    public StatusChecker(QualysApiInvoker qualysApiInvoker, String qualysScanId, String jobId, long initialDelay,
            long delayBetweenRuns) {
        this.qualysApiInvoker = qualysApiInvoker;
        this.jobId = jobId;
        this.qualysScanId = qualysScanId;
        this.initialDelay = initialDelay;
        this.delayBetweenRuns = delayBetweenRuns;
        this.scheduler = Executors.newScheduledThreadPool(NUM_THREADS);
        currentStatus.set("INITIATED");
    }

    public void activateStatusChecker() {
        log.info("-------------------");
        Runnable checkStatusTask = new CheckStatusTask();
        scheduler.scheduleWithFixedDelay(checkStatusTask, initialDelay, delayBetweenRuns, TimeUnit.MINUTES);
        log.info("activated status checker");

    }

    private final class CheckStatusTask implements Runnable {

        @Override public void run() {

            log.info("Start checking the status of the scan.");
            String status;
            try {
                status = qualysApiInvoker.retrieveStatus(QualysScanner.host, qualysScanId);
                currentStatus.set(status);
                switch (currentStatus.get()) {
                case "SUBMITTED":
                    CallbackUtil.updateScanStatus(jobId, ScanStatus.SUBMITTED, null, qualysScanId);
                    break;
                case "RUNNING":
                    CallbackUtil.updateScanStatus(jobId, ScanStatus.RUNNING, null, qualysScanId);
                    break;
                case "FINISHED":
                    CallbackUtil.updateScanStatus(jobId, ScanStatus.COMPLETED, null, qualysScanId);
                    CallbackUtil.persistScanLog(jobId, "SCAN IS COMPLETED", ScannerConstants.INFO);
                    scheduler.shutdown();
                    break;
                case "ERROR":
                    CallbackUtil.updateScanStatus(jobId, ScanStatus.ERROR, null, qualysScanId);
                    CallbackUtil.persistScanLog(jobId, "SCAN FAILED", ScannerConstants.ERROR);
                    scheduler.shutdown();
                    break;
                case "CANCELED":
                    log.info("SCAN IS FINISHED");
                    CallbackUtil.updateScanStatus(jobId, ScanStatus.CANCELED, null, qualysScanId);
                    CallbackUtil.persistScanLog(jobId, "SCAN IS CANCELLED", ScannerConstants.INFO);
                    scheduler.shutdown();
                    break;
                }
            } catch (IOException | InvalidRequestException | ParserConfigurationException | SAXException e) {
                CallbackUtil.updateScanStatus(jobId, ScanStatus.ERROR, null, qualysScanId);
                CallbackUtil.persistScanLog(jobId, "Could not retrieve the status", ScannerConstants.ERROR);
                scheduler.shutdown();
            }
        }
    }
}
