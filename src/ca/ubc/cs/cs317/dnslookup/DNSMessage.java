package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;
    public static final int QUERY = 0;

    private int id;
    private boolean QR;
    private int OPCODE;
    private boolean AA;
    private boolean TC;
    private boolean RD;
    private boolean RA;
    private int Z;
    private int RCODE;
    private int QDCOUNT;
    private int ANCOUNT;
    private int NSCOUNT;
    private int ARCOUNT;

    private final Map<String, Integer> nameToPosition = new HashMap<>();
    private final Map<Integer, String> positionToName = new HashMap<>();
    private final ByteBuffer buffer;


    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */
    public DNSMessage(short id) {
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);

        // Put id into the buffer
        this.id = Short.toUnsignedInt(id);
        buffer.putShort(id);

        // Fill the other header fields(5 rows other than the id) with 0s
        for (int i = 0; i < 5; i++) {
            buffer.putShort((short) 0);
        }
    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        buffer = ByteBuffer.wrap(recvd, 0, length);
        // First row for ID
        int id = Short.toUnsignedInt(buffer.getShort());
        this.setID(id);

        // Second Row, first byte for QR, OPCODE, AA, TC, RD
        byte first = buffer.get();
        // QR
        int qr = (first & 0x80) >> 7;
        this.setQR(qr == 1);
        // OPCODE
        int opcode = (first & 0x78) >> 3;
        this.setOpcode(opcode);
        // AA
        int aa = (first & 0x04) >> 2;
        this.setAA(aa == 1);
        // TC
        int tc = (first & 0x02) >> 1;
        this.setTC(tc == 1);
        // RD
        int rd = first & 0x01;
        this.setRD(rd == 1);

        // Second row, second byte for RA, Z, RCODE
        byte second = buffer.get();
        // RA
        int ra = (second & 0x80) >> 7;
        this.setRA(ra == 1);
        // Z (0 by default)
        this.Z = 0;
        // RCODE
        int rcode = second & 0x0F;
        this.setRcode(rcode);

        // Third row for QDCOUNT
        this.setQDCount(Short.toUnsignedInt(buffer.getShort()));

        // Fourth row for ANCOUNT
        this.ANCOUNT = Short.toUnsignedInt(buffer.getShort());

        // Fifth row for NSCOUNT
        this.NSCOUNT = Short.toUnsignedInt(buffer.getShort());

        // Sixth row for ARCOUNT
        this.setARCount(Short.toUnsignedInt(buffer.getShort()));
    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
     */
    public int getID() {
        return Short.toUnsignedInt(buffer.getShort(0));
    }

    public void setID(int id) {
        this.id = id;
    }

    public boolean getQR() {
        return this.QR;
    }

    public void setQR(boolean qr) {
        this.QR = qr;
    }

    public boolean getAA() {
        return this.AA;
    }

    public void setAA(boolean aa) {
        this.AA = aa;
    }

    public int getOpcode() {
        return this.OPCODE;
    }

    public void setOpcode(int opcode) {
        this.OPCODE = opcode;
    }

    public boolean getTC() {
        return this.TC;
    }

    public void setTC(boolean tc) {
        this.TC = tc;
    }

    public boolean getRD() {
        return this.RD;
    }

    public void setRD(boolean rd) {
        this.RD = rd;
    }

    public boolean getRA() {
        return this.RA;
    }

    public void setRA(boolean ra) {
        this.RA = ra;
    }

    public int getRcode() {
        return this.RCODE;
    }

    public void setRcode(int rcode) {
        this.RCODE = rcode;
    }

    public int getQDCount() {
        return this.QDCOUNT;
    }

    public void setQDCount(int count) {
        this.QDCOUNT = count;
    }

    public int getANCount() {
        return this.ANCOUNT;
    }

    public int getNSCount() {
        return this.NSCOUNT;
    }

    public int getARCount() {
        return this.ARCOUNT;
    }

    public void setARCount(int count) {
        this.ARCOUNT = count;
    }

    /**
     * Return the name at the current position() of the buffer.  This method is provided for you,
     * but you should ensure that you understand what it does and how it does it.
     *
     * The trick is to keep track of all the positions in the message that contain names, since
     * they can be the target of a pointer.  We do this by storing the mapping of position to
     * name in the positionToName map.
     *
     * @return The decoded name
     */
    public String getName() {
        // Remember the starting position for updating the name cache
        int start = buffer.position();
        int len = buffer.get() & 0xff;
        if (len == 0) return "";
        if ((len & 0xc0) == 0xc0) {  // This is a pointer
            int pointer = ((len & 0x3f) << 8) | (buffer.get() & 0xff);
            String suffix = positionToName.get(pointer);
            assert suffix != null;
            positionToName.put(start, suffix);
            return suffix;
        }
        byte[] bytes = new byte[len];
        buffer.get(bytes, 0, len);
        String label = new String(bytes, StandardCharsets.UTF_8);
        String suffix = getName();
        String answer = suffix.isEmpty() ? label : label + "." + suffix;
        positionToName.put(start, answer);
        return answer;
    }

    /**
     * The standard toString method that displays everything in a message.
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer so we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not change
        // the position in the buffer.  We remember what it was and put it back when we are done.
        int end = buffer.position();
        final int DataOffset = 12;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR()).append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        }
        finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we looking at)
     * @param nrrs Number of resource records
     * @param sb Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n");
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Decode and return the question that appears next in the message.  The current position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {
        String qname = getName();
        RecordType qtype = RecordType.getByCode(Short.toUnsignedInt(buffer.getShort()));
        RecordClass qclass = RecordClass.getByCode(Short.toUnsignedInt(buffer.getShort()));

        return new DNSQuestion(qname, qtype, qclass);
    }

    /**
     * Decode and return the resource record that appears next in the message.  The current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {
        DNSQuestion rrQuestion = getQuestion();
        int ttl = (int) Integer.toUnsignedLong(buffer.getInt());
        int rdlength = Short.toUnsignedInt(buffer.getShort());

        byte[] rdataBytes = new byte[rdlength];
        buffer.get(rdataBytes, 0, rdlength);

        RecordType rrType = rrQuestion.getRecordType();
        if (rrType == RecordType.A || rrType == RecordType.AAAA) {
            try {
                InetAddress inetAddress = InetAddress.getByAddress(rdataBytes);
                return new ResourceRecord(rrQuestion, ttl, inetAddress);
            } catch (UnknownHostException e) {
                // Safely ignore the exception
            }
        } else if (rrType == RecordType.NS || rrType == RecordType.CNAME || rrType == RecordType.MX) {
            // Roll back the position by rdlength as it was moved forward by rdataBytes above
            // In MX case, also ignore the preference field by adding 2 more bytes to position
            int currentPosition = buffer.position();
            if (rrType == RecordType.MX) {
                buffer.position(currentPosition - rdlength + 2);
            } else {
                buffer.position(currentPosition - rdlength);
            }
            String result = getName();
            return new ResourceRecord(rrQuestion, ttl, result);
        }

        String rdata = byteArrayToHexString(rdataBytes);
        return new ResourceRecord(rrQuestion, ttl, rdata);
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    public static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    /**
     * Add an encoded name to the message. It is added at the current position and uses compression
     * as much as possible.  Compression is accomplished by remembering the position of every added
     * label.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        String label;
        while (name.length() > 0) {
            Integer offset = nameToPosition.get(name);
            if (offset != null) {
                int pointer = offset;
                pointer |= 0xc000;
                buffer.putShort((short)pointer);
                return;
            } else {
                nameToPosition.put(name, buffer.position());
                int dot = name.indexOf('.');
                label = (dot > 0) ? name.substring(0, dot) : name;
                buffer.put((byte)label.length());
                for (int j = 0; j < label.length(); j++) {
                    buffer.put((byte)label.charAt(j));
                }
                name = (dot > 0) ? name.substring(dot + 1) : "";
            }
        }
        buffer.put((byte)0);
    }

    /**
     * Add an encoded question to the message at the current position.
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {
        // Questions can only be added to a message if no resource records are contained in the message
        if (this.getARCount() > 0) {
            return;
        }

        // Put the incremented question count in the buffer
        int incrementedQDCount = this.getQDCount() + 1;
        int qdCountFirstByte = incrementedQDCount & 0x00FF;
        int qdCountSecondByte = (incrementedQDCount & 0xFF00) >> 8;
        buffer.put(4, (byte) qdCountSecondByte);
        buffer.put(5, (byte) qdCountFirstByte);
        this.setQDCount(incrementedQDCount);

        // Put the question in the buffer
        addName(question.getHostName());

        // Put the type in the buffer
        addQType(question.getRecordType());

        // Put the class in the buffer
        addQClass(question.getRecordClass());
    }

    /**
     * Add an encoded resource record to the message at the current position.
     * @param rr The resource record to be added
     * @param section A string describing the section that the rr should be added to
     */
    public void addResourceRecord(ResourceRecord rr, String section) {
        // Put the incremented number of resource records in the buffer
        switch (section) {
            case "answer":
                int incrementedANCount = this.getARCount() + 1;
                int anCountFirstByte = incrementedANCount & 0x00FF;
                int anCountSecondByte = (incrementedANCount & 0xFF00) >> 8;
                buffer.put(6, (byte) anCountSecondByte);
                buffer.put(7, (byte) anCountFirstByte);
                this.ANCOUNT = incrementedANCount;
                break;
            case "nameserver":
                int incrementedNSCount = this.getNSCount() + 1;
                int nsCountFirstByte = incrementedNSCount & 0x00FF;
                int nsCountSecondByte = (incrementedNSCount & 0xFF00) >> 8;
                buffer.put(8, (byte) nsCountSecondByte);
                buffer.put(9, (byte) nsCountFirstByte);
                this.NSCOUNT = incrementedNSCount;
                break;
            case "additional":
                // Put the incremented number of resource records in the buffer
                int incrementedARCount = this.getARCount() + 1;
                int arCountFirstByte = incrementedARCount & 0x00FF;
                int arCountSecondByte = (incrementedARCount & 0xFF00) >> 8;
                buffer.put(10, (byte) arCountSecondByte);
                buffer.put(11, (byte) arCountFirstByte);
                this.setARCount(incrementedARCount);
                break;
            default:
                // Return if the section name is incorrect
                return;
        }

        // Put the question in the buffer
        addName(rr.getHostName());

        // Put the type in the buffer
        addQType(rr.getRecordType());

        // Put the class in the buffer
        addQClass(rr.getRecordClass());

        // Put the ttl in the buffer
        buffer.putInt((int) rr.getRemainingTTL());

        // Put a dummy value for rdlength in the buffer
        buffer.putShort((short) 0);

        // Put the rdata in the buffer
        int rdataStartPosition = buffer.position();

        RecordType type = rr.getRecordType();
        if (type == RecordType.A || type == RecordType.AAAA) {
            InetAddress inetAddress = rr.getInetResult();
            buffer.put(inetAddress.getAddress());
        } else if (type == RecordType.NS || type == RecordType.CNAME || type == RecordType.MX) {
            if (type == RecordType.MX) {
                buffer.putShort((short) 0);
                addName(rr.getTextResult());
            } else {
                addName(rr.getTextResult());
            }
        } else {
            byte[] hexString = rr.getTextResult().getBytes();
            buffer.put(hexString);
        }

        int rdataEndPosition = buffer.position();

        // Put the real value for rdlength in the buffer
        short rdlength = (short) (rdataEndPosition - rdataStartPosition);
        buffer.putShort(rdataStartPosition - 2, rdlength);
    }

    /**
     * Add an encoded type to the message at the current position.
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {
        int qType = recordType.getCode();
        buffer.putShort((short) qType);
    }

    /**
     * Add an encoded class to the message at the current position.
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        int qClass = recordClass.getCode();
        buffer.putShort((short) qClass);
    }

    /**
     * Return a byte array that contains all the data comprising this message.  The length of the
     * array will be exactly the same as the current position in the buffer.
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {
        int startingPosition = buffer.position();
        byte[] bytes = new byte[startingPosition];

        buffer.position(0);
        buffer.get(bytes, 0, startingPosition);
        // Set the position back to the original position
        buffer.position(startingPosition);

        return bytes;
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[]{
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }
}
