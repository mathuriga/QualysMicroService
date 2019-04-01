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
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.scanner.QualysScanner;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.xml.parsers.ParserConfigurationException;

/**
 * TODO : Class level comment
 */
public class StatusChecker {
    private static final Log log = LogFactory.getLog(StatusChecker.class);
    private static final int NUM_THREADS = 1;
    private ScheduledExecutorService scheduler;
    private final long initialDelay;
    private final long delayBetweenRuns;
    private static AtomicReference<String> currentStatus = new AtomicReference<>();
    private static QualysApiInvoker qualysApiInvoker;
    private static String qualysScanId;
    private static String jobId;

    public StatusChecker(QualysApiInvoker qualysApiInvoker, String qualysScanId, String jobId, long initialDelay,
            long delayBetweenRuns) {
        this.qualysApiInvoker = qualysApiInvoker;
        this.jobId = jobId;
        this.qualysScanId = qualysScanId;
        this.initialDelay = initialDelay;
        this.delayBetweenRuns = delayBetweenRuns;
        this.scheduler = Executors.newScheduledThreadPool(NUM_THREADS);
        String init = "INITIATED";
        currentStatus.set(init);
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
                    log.info("SCAN IS SUBMITTED");
                    break;
                case "RUNNING":
                    log.info("SCAN IS RUNNING");
                    break;
                case "FINISHED":
                    log.info("SCAN IS FINISHED");
                    scheduler.shutdown();
                    break;
                case "ERROR":
                    log.info("ERROR");
                    scheduler.shutdown();
                    break;
                case "CANCELED":
                    log.info("ERROR");
                    scheduler.shutdown();
                    break;
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InvalidRequestException e) {
                e.printStackTrace();
            } catch (ParserConfigurationException e) {
                e.printStackTrace();
            } catch (SAXException e) {
                e.printStackTrace();
            }
        }
    }
}
