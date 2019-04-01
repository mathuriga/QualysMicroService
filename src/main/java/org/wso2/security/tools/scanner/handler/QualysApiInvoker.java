package org.wso2.security.tools.scanner.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Consts;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.security.tools.scanner.QualysScannerConstants;
import org.wso2.security.tools.scanner.exception.InvalidRequestException;
import org.wso2.security.tools.scanner.exception.ScannerException;
import org.wso2.security.tools.scanner.utils.ScannerResponse;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * TODO : Class level comment
 */
public class QualysApiInvoker {

    private static final Log log = LogFactory.getLog(QualysApiInvoker.class);

    private String basicAuth;

    public String getBasicAuth() {
        return basicAuth;
    }

    public void setBasicAuth(String basicAuth) {
        this.basicAuth = basicAuth;
    }

    /**
     * Get prerequisites from Qualys backend.
     *
     * @return a boolean value to indicate the operation success
     * @throws ScannerException
     */
    public void generatePrerequestieFile(String endPoint, String filePath) throws ScannerException {
        String result;
        File tempFile = new File(filePath);
        boolean exists = tempFile.exists();
        try {
            if (!exists) {
                HttpPost postRequest = new HttpPost(endPoint);
                postRequest.addHeader("Authorization", "Basic " + basicAuth);
                postRequest.addHeader("Accept", "application/xml");
                HttpClient client = HttpClientBuilder.create().build();
                HttpResponse response = client.execute(postRequest);

                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    BufferedReader br = new BufferedReader(
                            new InputStreamReader(response.getEntity().getContent(), "UTF-8"));
                    StringBuffer res = new StringBuffer();

                    while ((result = br.readLine()) != null) {
                        res.append(result);
                    }

                    BufferedWriter bwr = new BufferedWriter(new FileWriter(new File(filePath)));
                    bwr.write(res.toString());
                    log.debug("File is created in " + filePath);
                    bwr.flush();
                    bwr.close();
                    br.close();

                } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                    log.error("Bad request in getting available web application");
                } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                    log.error("The API request failed because of an authentication failure");
                } else {
                    log.error("Unable to retrieve web application details");
                }
            }
        } catch (IOException e) {
            throw new ScannerException(
                    "Error while retrieving the prerequisites from Qualys end (List of Web Applications, "
                            + "List of Authentication Scripts, List of Crawling scripts!", e);
        }
    }

    public String addAuthenticationScript(String host, String authScriptRequestBody) throws ScannerException {
        HttpPost postRequest = new HttpPost(host.concat(QualysScannerConstants.QUALYS_ADD_AUTH_SCRIPT_API));
        postRequest.addHeader("Authorization", "Basic " + basicAuth);
        HttpClient client = HttpClientBuilder.create().build();
        StringEntity entity = new StringEntity(authScriptRequestBody, ContentType.create("text/xml", Consts.UTF_8));
        HttpResponse response;
        try {
            postRequest.setEntity(entity);

            response = client.execute(postRequest);
            return getRequiredData(response, "id");
        } catch (ParserConfigurationException | InvalidRequestException | SAXException | IOException e) {
            throw new ScannerException("Error occurred while adding authentication script", e);
        }

    }

    public String updateWebApp(String host, String updateWebAppRequestBody, String webId) throws ScannerException {
        HttpPost postRequest = new HttpPost(host.concat(QualysScannerConstants.QUALYS_WEB_UPDATE_API.concat(webId)));
        postRequest.addHeader("Authorization", "Basic " + basicAuth);
        HttpClient client = HttpClientBuilder.create().build();
        StringEntity entity = new StringEntity(updateWebAppRequestBody, ContentType.create("text/xml", Consts.UTF_8));
        HttpResponse response;
        try {
            postRequest.setEntity(entity);
            response = client.execute(postRequest);
            return getRequiredData(response, "id");
        } catch (IOException | ParserConfigurationException | InvalidRequestException | SAXException e) {
            throw new ScannerException("Error occurred while updating web app with authentication script", e);
        }
    }

    public ScannerResponse launchScan(String host, String launchScanRequestBody)
            throws ScannerException, InvalidRequestException {
        HttpPost postRequest = new HttpPost(host.concat(QualysScannerConstants.QUALYS_START_SCAN_API));
        postRequest.addHeader("Authorization", "Basic " + basicAuth);
        HttpClient client = HttpClientBuilder.create().build();
        StringEntity entity = new StringEntity(launchScanRequestBody, ContentType.create("text/xml", Consts.UTF_8));
        HttpResponse response;
        ScannerResponse scannerResponse = new ScannerResponse();
        String scanId;
        try {
            postRequest.setEntity(entity);
            response = client.execute(postRequest);
            scanId = getRequiredData(response, "id");
            if (scanId != null) {
                scannerResponse.setScanID(scanId);
                scannerResponse.setIsSuccessful(true);
            }
            return scannerResponse;
        } catch (IOException | ParserConfigurationException | SAXException e) {
            throw new ScannerException("Error occurred while launch scan", e);
        }
    }

    public String retrieveStatus(String host, String scanId)
            throws IOException, InvalidRequestException, ParserConfigurationException, SAXException {
        HttpGet getRequest = new HttpGet(host.concat(QualysScannerConstants.QUALYS_GET_STATUS_API.concat(scanId)));
        getRequest.addHeader("Authorization", "Basic " + basicAuth);
        getRequest.addHeader("Accept", "application/xml");
        HttpClient client = HttpClientBuilder.create().build();
        String status = null;
        HttpResponse response = client.execute(getRequest);
        status = getRequiredData(response, "status");
        return status;
    }

    private String getRequiredData(HttpResponse response, String tagName)
            throws InvalidRequestException, IOException, ParserConfigurationException, SAXException {
        String result;
        String requiredData = null;
        String responseCode = null;

        if (response.getStatusLine().getStatusCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), "UTF-8"));
            StringBuffer res = new StringBuffer();

            while ((result = br.readLine()) != null) {
                res.append(result);
            }

            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                    .parse(new InputSource(new StringReader(res.toString())));
            NodeList errNodes = doc.getElementsByTagName("ServiceResponse");

            if (errNodes.getLength() > 0) {
                Element err = (Element) errNodes.item(0);
                responseCode = err.getElementsByTagName("responseCode").item(0).getTextContent();
                if (responseCode != null) {
                    if (responseCode.equals("SUCCESS")) {
                        requiredData = err.getElementsByTagName(tagName).item(0).getTextContent();
                    } else if (responseCode.equals("INVALID_XML")) {
                        log.error("Invalid XML format in the XML request");
                    } else if (responseCode.equals("UNAUTHORIZED")) {
                        log.error("Unauthorized to access the Start Scan API");
                        //todo INVALID_REQUEST and through res
                    }
                }
            }
        } else if (response.getStatusLine().getStatusCode() == 400) {
            log.error("The API request did not contain one or more parameters which are required.");
            throw new InvalidRequestException(
                    "The API request did not contain one or more parameters which are required.");
        } else if (response.getStatusLine().getStatusCode() == 202) {
            log.error("Request is being processed. The API request is for a business operation which is "
                    + "already underway.");
        } else if (response.getStatusLine().getStatusCode() == 501) {
            log.error("The API request failed due to a problem with QWEB.");
        } else if (response.getStatusLine().getStatusCode() == 401) {
            log.error("The API request failed because of an authentication failure");
        } else {
            log.error("Unable to retrieve data");
        }
        return requiredData;

    }
}
