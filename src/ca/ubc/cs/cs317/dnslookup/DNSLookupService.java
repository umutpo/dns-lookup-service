package ca.ubc.cs.cs317.dnslookup;

import javax.xml.crypto.Data;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class DNSLookupService {
    public static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    protected static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new SecureRandom();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;
    private InetAddress nameServer;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param nameServer The nameserver to be used initially. If set to null, "root" or "random", will choose a random
     *                   pre-determined root nameserver.
     * @param verbose    A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(String nameServer, DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
        this.setNameServer(nameServer);
    }

    /**
     * Returns the nameserver currently being used for queries.
     *
     * @return The string representation of the nameserver IP address.
     */
    public String getNameServer() {
        return this.nameServer.getHostAddress();
    }

    /**
     * Updates the nameserver to be used in all future queries.
     *
     * @param nameServer The nameserver to be used initially. If set to null, "root" or "random", will choose a random
     *                   pre-determined root nameserver.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public void setNameServer(String nameServer) throws UnknownHostException {

        // If none provided, choose a random root nameserver
        if (nameServer == null || nameServer.equalsIgnoreCase("random") || nameServer.equalsIgnoreCase("root")) {
            List<ResourceRecord> rootNameServers = cache.getCachedResults(DNSCache.rootQuestion, false);
            nameServer = rootNameServers.get(0).getTextResult();
        }
        this.nameServer = InetAddress.getByName(nameServer);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Finds all the results for a specific question. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are included in the results as CNAME records (i.e., not queried further).
     *
     * @param question Host and record type to be used for search.
     * @return A (possibly empty) set of resource records corresponding to the specific query requested.
     */
    public Collection<ResourceRecord> getResults(DNSQuestion question) {

        Collection<ResourceRecord> results = cache.getCachedResults(question, true);
        if (results.isEmpty()) {
            iterativeQuery(question, nameServer);
            results = cache.getCachedResults(question, true);
        }
        return results;
    }

    /**
     * Finds all the results for a specific question. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting resource records of the indicated type.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws CNameIndirectionLimitException If the number CNAME redirection levels exceeds the value set in
     *                                        maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getResultsFollowingCNames(DNSQuestion question, int maxIndirectionLevels)
            throws CNameIndirectionLimitException {

        if (maxIndirectionLevels < 0) throw new CNameIndirectionLimitException();

        Collection<ResourceRecord> directResults = getResults(question);
        if (directResults.isEmpty() || question.getRecordType() == RecordType.CNAME)
            return directResults;

        List<ResourceRecord> newResults = new ArrayList<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getResultsFollowingCNames(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Retrieves DNS results from a specified DNS server using the iterative mode. After an individual query is sent and
     * its response is received (or times out), checks if an answer for the specified host exists. Resulting values
     * (including answers, nameservers and additional information provided by the nameserver) are added to the cache.
     * <p>
     * If after the first query an answer exists to the original question (either with the same record type or an
     * equivalent CNAME record), the function returns with no further actions. If there is no answer after the first
     * query but the response returns at least one nameserver, a follow-up query for the same question must be done to
     * another nameserver. Note that nameservers returned by the response contain text records linking to the host names
     * of these servers. If at least one nameserver provided by the response to the first query has a known IP address
     * (either from this query or from a previous query), it must be used first, otherwise additional queries are
     * required to obtain the IP address of the nameserver before it is queried. Only one nameserver must be contacted
     * for the follow-up query.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the first query.
     */
    public void iterativeQuery(DNSQuestion question, InetAddress server) {
        // Step 1: See if the answer is in local information, and if so return.
        List<ResourceRecord> cachedAnswers = cache.getCachedResults(question, true);
        if (!cachedAnswers.isEmpty()) {
            return;
        }

        // Step 2: Look for an answer by making a query and return if one found.
        Set<ResourceRecord> nameSpaceRecords = individualQueryProcess(question, server);
        cachedAnswers = cache.getCachedResults(question, true);
        if (!cachedAnswers.isEmpty()) {
            return;
        }

        // Step 3: If no answer is found, look for a nameserver that is returned. If one exists, either...
        if (nameSpaceRecords != null) {
            // Step 4.a: ...check the cache for its IP address. If it is in cache, make a new call to that
            //           nameserver.
            ResourceRecord nameSpaceRecord = null;
            for (ResourceRecord record : nameSpaceRecords) {
                nameSpaceRecord = record;
                DNSQuestion nameSpaceQuestion = new DNSQuestion(nameSpaceRecord.getTextResult(), RecordType.A, RecordClass.IN);
                List<ResourceRecord> nameSpaceAnswers = cache.getCachedResults(nameSpaceQuestion, false);
                if (!nameSpaceAnswers.isEmpty()) {
                    iterativeQuery(question, nameSpaceAnswers.get(0).getInetResult());
                    return;
                }
            }

            // Step 4.b: ...or retrieve its IP address by making another query. After receiving it, make a
            //           new call to that nameserver.
            if (nameSpaceRecord != null) {
                DNSQuestion nameSpaceQuestion = new DNSQuestion(nameSpaceRecord.getTextResult(), RecordType.A, RecordClass.IN);
                iterativeQuery(nameSpaceQuestion, server);
                List<ResourceRecord> nameSpaceAnswers = cache.getCachedResults(nameSpaceQuestion, false);
                if (!nameSpaceAnswers.isEmpty()) {
                    iterativeQuery(question, nameSpaceAnswers.get(0).getInetResult());
                    return;
                }
            }
        }
    }

    /**
     * Handles the process of sending an individual DNS query with a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     * <p>
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of resource records for all
     * nameservers received in the response. Only records found in the nameserver section of the response are included,
     * and only those whose record type is NS. If a response is received but there are no nameservers, returns an empty
     * set.
     */
    protected Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server) {
        DNSMessage message = buildQuery(question);
        byte[] requestPacketLoad = message.getUsed();

        DNSMessage responseMessage = null;
        for (int i = 0; i < MAX_QUERY_ATTEMPTS; i++) {
            try {
                verbose.printQueryToSend(question, server, message.getID());

                responseMessage = trySendingAndReceivingMessage(requestPacketLoad, server);
                if (responseMessage.getID() == message.getID()
                        && responseMessage.getQR()
                        && responseMessage.getRcode() == 0) {
                    // A response is received successfully, break the loop and process this message
                    break;
                } else {
                    // Try again in the next iteration of the loop
                    responseMessage = null;
                }
            } catch (SocketTimeoutException e) {
                // Try again in the next iteration of the loop
            } catch (IOException e) {
                break;
            }
        }

        if (responseMessage == null) {
            return null;
        }

        return processResponse(responseMessage);
    }

    /**
     *  Sends the Datagram Packet through the socket. After receiving the response, parses the response to DNS Message.
     * @param requestPacketLoad Datagram packet to send as byte array
     * @param server DNS Server to make the query to
     * @return The DNSMessage containing the response
     * @throws IOException
     */
    private DNSMessage trySendingAndReceivingMessage(byte[] requestPacketLoad, InetAddress server) throws IOException {
        // Send the packet
        DatagramPacket requestPacket = new DatagramPacket(requestPacketLoad, requestPacketLoad.length, server, DEFAULT_DNS_PORT);
        socket.setSoTimeout(SO_TIMEOUT);
        socket.send(requestPacket);

        // Receive the packet
        byte[] responseLoad = new byte[512];
        DatagramPacket responsePacket = new DatagramPacket(responseLoad, responseLoad.length);
        socket.receive(responsePacket);

        return new DNSMessage(responsePacket.getData(), responsePacket.getLength());
    }

    /**
     * Creates a DNSMessage containing a DNS query.
     * A random transaction ID must be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the message's buffer's position (`message.buffer.position`) must be equivalent
     * to the size of the query data.
     *
     * @param question Host name and record type/class to be used for the query.
     * @return The DNSMessage containing the query.
     */
    protected DNSMessage buildQuery(DNSQuestion question) {
        short id = (short) random.nextInt(65535);
        DNSMessage newMessage = new DNSMessage(id);
        newMessage.addQuestion(question);
        return newMessage;
    }

    /**
     * Parses and processes a response received by a nameserver. Adds all resource records found in the response message
     * to the cache. Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param response The DNSMessage received from the server.
     * @return A set of resource records for all nameservers received in the response. Only records found in the
     * nameserver section of the response are included, and only those whose record type is NS. If there are no
     * nameservers, returns an empty set.
     */
    protected Set<ResourceRecord> processResponse(DNSMessage response) {
        Set<ResourceRecord> responseRecords = new HashSet<ResourceRecord>();

        // Print header info
        verbose.printResponseHeaderInfo(response.getID(), response.getAA(), response.getRcode());

        // Skip the questions
        for (int i = 0; i < response.getQDCount(); i++) {
            DNSQuestion question = response.getQuestion();
        }

        // Process answer responses
        int answerCount = response.getANCount();
        verbose.printAnswersHeader(answerCount);
        for (int i = 0; i < answerCount; i++) {
            ResourceRecord record = response.getRR();
            RecordType type = record.getRecordType();
            if (type == RecordType.SOA || type == RecordType.OTHER) {
                byte[] data = record.getTextResult().getBytes();
                String result = byteArrayToHexString(data);
                ResourceRecord newRecord = new ResourceRecord(record.getQuestion(), (int) record.getRemainingTTL(), result);
                response.addResourceRecord(newRecord, "answer");
            }

            verbose.printIndividualResourceRecord(record, record.getRecordType().getCode(), record.getRecordClass().getCode());
            cache.addResult(record);
        }

        // Process nameserver responses
        int nameserverCount = response.getNSCount();
        verbose.printNameserversHeader(nameserverCount);
        for (int i = 0; i < nameserverCount; i++) {
            ResourceRecord record = response.getRR();
            RecordType type = record.getRecordType();
            if (type == RecordType.SOA || type == RecordType.OTHER) {
                byte[] data = record.getTextResult().getBytes();
                String result = byteArrayToHexString(data);
                ResourceRecord newRecord = new ResourceRecord(record.getQuestion(), (int) record.getRemainingTTL(), result);
                response.addResourceRecord(newRecord, "nameserver");
            } else if (type == RecordType.NS) {
                responseRecords.add(record);
            }

            verbose.printIndividualResourceRecord(record, record.getRecordType().getCode(), record.getRecordClass().getCode());
            cache.addResult(record);
        }

        // Process additional responses
        int additionalCount = response.getARCount();
        verbose.printAdditionalInfoHeader(additionalCount);
        for (int i = 0; i < additionalCount; i++) {
            ResourceRecord record = response.getRR();
            RecordType type = record.getRecordType();
            if (type == RecordType.SOA || type == RecordType.OTHER) {
                byte[] data = record.getTextResult().getBytes();
                String result = byteArrayToHexString(data);
                ResourceRecord newRecord = new ResourceRecord(record.getQuestion(), (int) record.getRemainingTTL(), result);
                response.addResourceRecord(newRecord, "additional");
            }

            verbose.printIndividualResourceRecord(record, record.getRecordType().getCode(), record.getRecordClass().getCode());
            cache.addResult(record);
        }

        return responseRecords;
    }

    /**
     * Helper function that converts a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by the nameserver but not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    private static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    public static class CNameIndirectionLimitException extends Exception {
    }
}
