package tcp_cifrado;

import DiffieHellman.DiffieHellman;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * TCP server that encrypts messages received from the client 
 * by changing the vowels for numbers. The characteristic of 
 * the server is that it receives the encrypted message and 
 * decrypts it with the key used by the client. This is 
 * implemented with the Diffie-Hellman algorithm, which is 
 * programmed in the DiffieHellman.java class.
 *
 * @version 1.6 18/04/2022
 * @author Raquel Romero Pedraza
 *
 */
public class ServidorTCP {

    /**
     * Principal method
     *
     * @param args
     *
     * @throws java.security.NoSuchProviderException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.lang.ClassNotFoundException
     */
    public static void main(String[] args) throws NoSuchProviderException, InvalidKeySpecException, ClassNotFoundException {

        // Puerto donde escuchará el servidor:
        int puerto = 8888;

        ServerSocket socketEscucha;

        try {

            ////// Inicializamos el socket de escucha ////////////
            mostrar("Abriendo puerto...", false);

            socketEscucha = new ServerSocket(puerto);

            mostrar("¡Abierto!", true);

            ////////////////////////////////////////////////////////////////////
            // Servidor iterativo
            boolean salirServicio = false;
            mostrar("Entrando en bucle de servicio a clientes...", false);

            while (!salirServicio) {

                // Aceptamos nueva conexión: 
                mostrar(" ", true);
                mostrar("Esperando conexiones entrantes... ", false);

                // Obtenemos los canales de entrada y salida:
                try (Socket socketConexion = socketEscucha.accept()) {

                    mostrar("¡Conexión aceptada!", true);

                    /////////////////////////////////////////////////////////////////////
                    /////// INTERCAMBIO DE CLAVES DIFFIE-HELLMAN ///////////////////////
                    ///////////////////////////////////////////////////////////////////
                    final DiffieHellman server = new DiffieHellman();
                    mostrar("Realizando intercambio de claves Diffie-Hellman\n", false);

                    // Creamos un canal para intercambio de objetos ya que se va
                    // a intercambiar un clave (objeto PublicKey)
                    PublicKey publicKey_Cliente;

                    server.generateKeys();

                    OutputStream keyOut = socketConexion.getOutputStream();
                    ObjectOutputStream outO = new ObjectOutputStream(keyOut);

                    // Manda la clave pública del server
                    outO.writeObject(server.getPublicKey());
                    outO.writeUnshared(server.getPublicKey());
                    outO.flush();

                    ObjectInputStream In = new ObjectInputStream(socketConexion.getInputStream());

                    // Recibela clave pública del cliente
                    publicKey_Cliente = (PublicKey) In.readObject();
                    server.receivePublicKeyFrom(publicKey_Cliente);

                    // Genera la clave secreta compartida
                    server.generateCommonSecretKey();
                    mostrar("Intercambio Diffie-Hellaman terminado\n", false);

                    ////////////////
                    // DESCIFRADO //
                    ////////////////
                    // Leemos una petición:
                    mostrar("Esperando mensaje ", false);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socketConexion.getInputStream()));
                    String linea = in.readLine();

                    byte[] decode = Base64.getDecoder().decode(linea);
                    linea = descifrar(decode, server);

                    String mensajeRespuesta = "";

                    ////////////////////////////////////////////////////////////////
                    // Estado: Funcionando
                    // Analizamos mensaje: 
                    
                    if (linea.equals("adios")) {
                        mostrar("¡Recibido mensaje de cierre!", true);
                        mostrar("Cerrando conexion...", false);
                        salirServicio = true;
                        mostrar("¡Hecho!", true);
                    } else if (!linea.equals("adios")) {

                        mostrar("¡Recibido!", true);
                        mostrar("Sustituyendo vocales...", false);
                        mensajeRespuesta = sustituye(linea);
                        mostrar("¡Hecho!", true);

                    } else {
                        mensajeRespuesta = "Error";
                        mostrar("¡Mensaje recibido incorrecto!", true);
                    }

                    // Enviamos la respuesta:
                    PrintWriter out = new PrintWriter(socketConexion.getOutputStream());
                    out.println(mensajeRespuesta);
                    out.flush();

                    in.close();
                    out.close();

                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(ServidorTCP.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            mostrar("Cerrando socket... ", false);
            socketEscucha.close();
            mostrar("¡Cerrado! ", true);
        } catch (IOException ex) {
            Logger.getLogger(ServidorTCP.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Procesa una frase y la cifra cambiando las vocales por números.
     *
     * @param textoPlano Texto plano.
     * @return Texto cifrado.
     */
    private static String sustituye(String textoPlano) {
        String resultado;

        resultado = textoPlano.replace("a", "1");
        resultado = resultado.replace("e", "2");
        resultado = resultado.replace("i", "3");
        resultado = resultado.replace("o", "4");
        resultado = resultado.replace("u", "5");

        return resultado;
    }

    /**
     * Método auxiliar para mostrar mensajes por pantalla:
     *
     * @param mensaje
     */
    private static void mostrar(String mensaje, boolean simple) {
        System.out.print(((simple) ? "" : "Servidor: ") + mensaje + ((simple) ? "\n" : ""));
    }

    /**
     * Descifra un mensaje pasado en bytes[] con una clave DiffieHellman para el
     * algoritmo DES
     *
     * @param textoCifrado
     * @param person
     *
     * @return Texto descifrado.
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private static String descifrar(byte[] textoCifrado, DiffieHellman person) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        String textoDescifrado;

        final SecretKeySpec keySpec = new SecretKeySpec(person.getSecretKey(), "DES");
        final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        textoDescifrado = new String(cipher.doFinal(textoCifrado));

        return textoDescifrado;
    }

}
