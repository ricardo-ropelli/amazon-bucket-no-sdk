import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

public class AmazonS3Bucket {

    private static final String CLIENT_ID = "";
    private static final String CLIENT_SECRET = "";
    private static final String FILE_NAME = "";

    private static final String BUCKET_NAME = "";
    private static final String SERVICE_NAME = "s3";
    private static final String SERVICE_REGION = "";
    private static final String AWS_4_REQUEST = "aws4_request";

    private static final String HOST = BUCKET_NAME.concat(".").concat(SERVICE_NAME).concat(".amazonaws.com");
    private static final String REQUEST_DOMAIN = "https://".concat(HOST);
    private static final String REQUEST_URL = REQUEST_DOMAIN.concat("/").concat(BUCKET_NAME).concat("/").concat(FILE_NAME);

    private static final String SIGNED_HEADERS = "host;x-amz-content-sha256;x-amz-date;x-amz-storage-class";

    private static final DateFormat DATE_FORMAT_UTC = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.US);
    private static final DateFormat DATE_FORMAT_YYYYMMDD = new SimpleDateFormat("yyyyMMdd", Locale.US );

    private static final String PAYLOAD_DATA = "Welcome Amazon S3, your code is green!";

    private static List<Header> buildHeaders(String hashedPayload) {
        ArrayList<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("content-type", "application/x-www-form-urlencoded; charset=utf-8"));
        headers.add(new BasicHeader("host", HOST));
        headers.add(new BasicHeader("x-amz-content-sha256", hashedPayload));
        return headers;
    }

    public static void main(String[] args) throws Exception {
        printAllAttributes();

        DATE_FORMAT_UTC.setTimeZone(TimeZone.getTimeZone("UTC"));

        Date now = new Date();
        String dateUTC = DATE_FORMAT_UTC.format(now);
        String date = DATE_FORMAT_YYYYMMDD.format(now);


        // Perform processing:
        String hashedRequestBody = performSha256Hex(PAYLOAD_DATA);
        System.out.println("\n-------------------HashedRequestBody-------------------\n"
                + hashedRequestBody
                + "\n-----------------------------------------------------");

        // Task 1: Build canonical request.
        String canonicalRequest = buildCanonicalRequest(dateUTC, hashedRequestBody);
        System.out.println("\n-------------------CanonicalRequest-------------------\n"
                + canonicalRequest
                + "\n-----------------------------------------------------");

        String hashedCanonicalRequest = performSha256Hex(canonicalRequest);
        System.out.println("\n-------------------HashedCanonicalRequest-------------------\n"
                + hashedCanonicalRequest
                + "\n-----------------------------------------------------");

        // Step 2: Build string to sign.
        String stringToSign = buildStringToSign(dateUTC, date, hashedCanonicalRequest);
        System.out.println("\n-------------------StringToSign-------------------\n"
                + stringToSign
                + "\n-----------------------------------------------------");

        // Step 3: Calculate signature;
        byte[] derivedSigningKey = getDerivedSigningKey(date);
        String signature = Hex.encodeHexString(hmacSHA256(derivedSigningKey, stringToSign));
        System.out.println("\n-------------------Signature-------------------\n"
                + signature
                + "\n-----------------------------------------------------");

        // Step 4: Build Authorization header.
        String authorizationHeader = buildAuthorizationHeader(date, signature);
        System.out.println("\n-------------------AuthorizationHeader-------------------\n"
                + authorizationHeader
                + "\n-----------------------------------------------------");

        HttpPut request = buildRequest(dateUTC, hashedRequestBody, authorizationHeader);

        HttpClient httpclient = HttpClientBuilder.create().build();
        HttpResponse response = httpclient.execute(request);
        System.out.println("\n" + response.getStatusLine().getStatusCode());
        System.out.println(EntityUtils.toString(response.getEntity()));

    }

    private static HttpPut buildRequest(String dateUTC, String hashedRequestBody, String authorizationHeader) {
        HttpPut request = new HttpPut(REQUEST_URL);
        buildHeaders(hashedRequestBody).forEach(request::addHeader);
        request.addHeader(new BasicHeader("Authorization", authorizationHeader));
        request.addHeader(new BasicHeader("x-amz-date", dateUTC));
        request.addHeader(new BasicHeader("x-amz-storage-class", "REDUCED_REDUNDANCY"));
        StringEntity jsonData = new StringEntity(PAYLOAD_DATA, "UTF-8");
        request.setEntity(jsonData);
        return request;
    }

    private static String buildAuthorizationHeader(String date, String signature) {
        /* Template:
        Authorization: AWS4-HMAC-SHA256 <space>
        Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request,<space>
        SignedHeaders=content-type;host;x-amz-date,<space>
        Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7*/

        final String template = "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/%s,SignedHeaders=%s,Signature=%s";
        return String.format(template,
                CLIENT_ID, date, SERVICE_REGION, SERVICE_NAME, AWS_4_REQUEST, // Credential Line
                SIGNED_HEADERS, // SignedHeaders Line
                signature); // Signature Line
    }

    private static String buildStringToSign(String dateUTC, String date, String hashedCanonicalRequest) {
        /* Template:
        StringToSign =
            Algorithm + \n +
            RequestDateTime + \n +
            CredentialScope + \n +
            HashedCanonicalRequest*/

        return "AWS4-HMAC-SHA256\n"
                + dateUTC.concat("\n")
                + date.concat("/").concat(SERVICE_REGION)
                    .concat("/").concat(SERVICE_NAME)
                    .concat("/").concat(AWS_4_REQUEST).concat("\n")
                + hashedCanonicalRequest;
    }

    private static String buildCanonicalRequest(String dateUTC, String hashedRequestBody) {
        /* Template:
        CanonicalRequest =
              HTTPRequestMethod + '\n' +
              CanonicalURI + '\n' +
              CanonicalQueryString + '\n' +
              CanonicalHeaders + '\n' +
              SignedHeaders + '\n' +
              HexEncode(Hash(RequestPayload))*/

        String template =
                "PUT\n"
                + "/%s/%s\n"
                + "\n"
                + "host:%s\n"
                + "x-amz-content-sha256:%s\n"
                + "x-amz-date:%s\n"
                + "x-amz-storage-class:%s\n"
                + "\n"
                + "%s\n"
                + "%s";

        return String.format(template,
                BUCKET_NAME, FILE_NAME,
                HOST,
                hashedRequestBody,
                dateUTC,
                "REDUCED_REDUNDANCY",
                SIGNED_HEADERS,
                hashedRequestBody);
    }

    private static void printAllAttributes() throws Exception {
        System.out.println("\n-------------------ClassAttributes-------------------");
        for (Field field : AmazonS3Bucket.class.getDeclaredFields()) {
            String fieldName = field.getName();
            System.out.println(fieldName.concat(" = ").concat(field.get(fieldName).toString()));
        }
        System.out.println("-----------------------------------------------------");
    }

    private static byte[] getDerivedSigningKey(String date) throws Exception {
        byte[] kSecret = ("AWS4" + CLIENT_SECRET).getBytes("utf-8");
        byte[] kDate = hmacSHA256(kSecret, date);
        byte[] kRegion = hmacSHA256(kDate, SERVICE_REGION);
        byte[] kService = hmacSHA256(kRegion, SERVICE_NAME);
        return hmacSHA256(kService, AWS_4_REQUEST);
    }

    private static byte[] hmacSHA256(byte[] key, String data) throws Exception {
        String algorithm = "hmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("utf-8"));
    }

    private static String performSha256Hex(String payloadData) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Hex.encodeHexString(digest.digest(payloadData.getBytes(StandardCharsets.UTF_8)));
    }
}