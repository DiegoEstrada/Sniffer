package sniffer;

/**
 *
 * @author Diego EG
 */
public class Sniffer {

    
    
     private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }

    return buf.toString();
  }
    public static void main(String[] args) {
        // TODO code application logic here
    }
    
}
