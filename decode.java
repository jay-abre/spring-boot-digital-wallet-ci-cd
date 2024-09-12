import java.util.Base64;

public class decode {
    public static void main(String[] args) {
        try {
            String encodedSecret = "0U80bTILf0lIo0PaUX9XvHS/+zXgEIACnocgVOMjXuY=";
            byte[] decodedKey = Base64.getDecoder().decode(encodedSecret);
            System.out.println("Decoded Key Length: " + decodedKey.length);
        } catch (Exception e) {
            System.err.println("Decoding error: " + e.getMessage());
        }
    }
}
